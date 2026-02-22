let src = Logs.Src.create "ptt"

module Log = (val Logs.src_log src : Logs.LOG)
open Colombe.Sigs
open Colombe

type info = Logic.info = {
    domain: Colombe.Domain.t
  ; ipaddr: Ipaddr.t
  ; tls: Tls.Config.server option
  ; zone: Mrmime.Date.Zone.t
  ; size: int
}

type email = Logic.email = {
    from: Reverse_path.t * (string * string option) list
  ; recipients: (Forward_path.t * (string * string option) list) list
  ; domain_from: Domain.t
}

type ('dns, 'err) getmxbyname =
     'dns
  -> [ `host ] Domain_name.t
  -> (Dns.Rr_map.Mx_set.t, ([> `Msg of string ] as 'err)) result

type ('dns, 'err) gethostbyname =
     'dns
  -> [ `host ] Domain_name.t
  -> (Ipaddr.t list, ([> `Msg of string ] as 'err)) result

type resolver =
  | Resolver : {
        getmxbyname: 'err. ('dns, 'err) getmxbyname
      ; gethostbyname: 'err. ('dns, 'err) gethostbyname
      ; dns: 'dns
    }
      -> resolver

module SMTP = Smtp
module SSMTP = Ssmtp

let ( let* ) = Result.bind

let run : type flow.
       (flow, Msendmail.Miou_scheduler.t) rdwr
    -> flow
    -> ('a, 'err) State.t
    -> ('a, 'err) result =
 fun rdwr flow t ->
  let open Msendmail.Miou_scheduler in
  let open Colombe.State in
  let rec go = function
    | Read { buffer; off; len; k } ->
        let res = prj (rdwr.rd flow buffer off len) in
        go (k res)
    | Write { buffer; off; len; k } ->
        let () = prj (rdwr.wr flow buffer off len) in
        go (k len)
    | Return v -> Ok v
    | Error err -> (Error err : _ result)
  in
  go t

type user's_error =
  [ `Aborted
  | `Not_enough_memory
  | `Too_big_data
  | `Failed
  | `Requested_action_not_taken of [ `Temporary | `Permanent ] ]

let pp_user's_error ppf = function
  | `Aborted -> Fmt.string ppf "Aborted"
  | `Not_enough_memory -> Fmt.string ppf "Not enough memory"
  | `Too_big_data -> Fmt.string ppf "Too big data"
  | `Failed -> Fmt.string ppf "Failed"
  | `Requested_action_not_taken `Temporary ->
      Fmt.string ppf "Requested action not taken (temporary)"
  | `Requested_action_not_taken `Permanent ->
      Fmt.string ppf "Requested action not taken (permanent)"

type oc = [ `Ok | user's_error ] Miou.Computation.t

let merge result user's_result =
  match (result, user's_result) with
  | Error `Too_big_data, _ -> `Too_big_data
  | Error `Not_enough_memory, _ -> `Not_enough_memory
  | Error `End_of_input, _ -> `Aborted
  | Error _, _ -> `Requested_action_not_taken `Temporary
  | Ok (), user's_result -> user's_result

exception Extension_is_not_available of Colombe.Forward_path.t
exception Invalid_recipients of Colombe.Forward_path.t
exception Recipients_unreachable

let recipients_unreachable =
  let bt = Printexc.get_callstack 0 in
  (Recipients_unreachable, bt)

let recipients_are_reachable ~info
    (Resolver { dns; gethostbyname; getmxbyname }) recipients =
  let domains =
    let open Colombe in
    let fn acc = function
      | Forward_path.Postmaster -> acc
      | Domain (Domain.IPv4 _ | Domain.IPv6 _)
      | Forward_path { Path.domain= Domain.IPv4 _ | Domain.IPv6 _; _ } ->
          acc
      | ( Domain (Domain.Extension _)
        | Forward_path { Path.domain= Domain.Extension _; _ } ) as value ->
          raise (Extension_is_not_available value)
      | ( Domain (Domain.Domain domain)
        | Forward_path { Path.domain= Domain.Domain domain; _ } ) as value ->
        begin
          if Domain.equal (Domain.Domain domain) info.domain then acc
          else
            let domain_name =
              let open Domain_name in
              Result.bind (of_strings domain) host
            in
            match domain_name with
            | Ok domain_name -> Domain_name.Host_set.add domain_name acc
            | Error _ -> raise (Invalid_recipients value)
        end
    in
    List.fold_left fn Domain_name.Host_set.empty recipients
    |> Domain_name.Host_set.elements
  in
  let mail_exchange_are_reachable { Dns.Mx.mail_exchange; _ } =
    let result = gethostbyname dns mail_exchange in
    Result.is_ok result
  in
  let domain_are_reachable domain =
    let result = getmxbyname dns domain in
    match result with
    | Ok mxs ->
        let lst = Dns.Rr_map.Mx_set.elements mxs in
        let lst = List.sort Dns.Mx.compare lst in
        List.exists mail_exchange_are_reachable lst
    | Error _ -> false
  in
  List.for_all domain_are_reachable domains

let recipients_are_reachable ~info dns recipients =
  match recipients_are_reachable ~info dns recipients with
  | value -> value
  | exception Extension_is_not_available recipient ->
      Log.warn (fun m ->
          m "Someone tries to send an email to an extension: %a"
            Colombe.Forward_path.pp recipient);
      false
  | exception Invalid_recipients recipient ->
      Log.warn (fun m ->
          m "%a's destination is unreachable" Colombe.Forward_path.pp recipient);
      false

module Relay = struct
  type ic = email Miou.Computation.t

  let properly_close_starttls ctx flow =
    let encoder = Sendmail_with_starttls.Context_with_tls.encoder ctx in
    let t = SMTP.Value_with_tls.close encoder in
    let t = SMTP.Monad.reword_error (fun err -> `Tls err) t in
    run Msendmail.tcp flow t

  type error =
    [ user's_error
    | `Invalid_recipients
    | `No_recipients
    | `Too_many_bad_commands
    | `Too_many_recipients
    | `Protocol of SMTP.Value_with_tls.error
    | `Tls of SMTP.Value_with_tls.error ]

  let pp_error ppf = function
    | #user's_error as err -> pp_user's_error ppf err
    | `Invalid_recipients -> Fmt.string ppf "Invalid recipients"
    | `No_recipients -> Fmt.string ppf "No recipients"
    | `Too_many_bad_commands -> Fmt.string ppf "Too many bad commands"
    | `Too_many_recipients -> Fmt.string ppf "Too many recipients"
    | `Protocol err | `Tls err -> SMTP.Value_with_tls.pp_error ppf err

  let handler ?encoder ?decoder ?queue ~info dns flow (ic, oc) q =
    let ctx =
      Sendmail_with_starttls.Context_with_tls.make ?encoder ?decoder ?queue ()
    in
    let t = SMTP.m_relay_init ctx info in
    Log.debug (fun m -> m "Initiate a new SMTP connection");
    let* operation = run Msendmail.tcp flow t in
    match operation with
    | `Quit -> properly_close_starttls ctx flow
    | `Send ({ SMTP.recipients; _ } as m)
      when recipients_are_reachable ~info dns (List.map fst recipients) ->
        assert (Miou.Computation.try_return ic m);
        let t = SMTP.m_mail ctx in
        let* () = run Msendmail.tcp flow t in
        (* TODO(dinosaure): can we replace [go] by a source which gives to us
           lines and transmit everything to a sink given by the user?
           [Flux.Flow.take] can be our limit and what happened when we reach
           it? Perhaps it is not so interesting to abstract all this. *)
        let rec go size =
          if size > info.size then begin
            Flux.Bqueue.close q; Error `Too_big_data
          end
          else
            let t = SMTP.(Monad.recv ctx Value.Payload) in
            let result = run Msendmail.tcp flow t in
            match result with
            | Ok ".." ->
                Flux.Bqueue.put q ".\r\n";
                go (size + 3)
            | Ok "." -> Flux.Bqueue.close q; Ok ()
            | Error _ as err -> Flux.Bqueue.close q; err
            | Ok line ->
                Flux.Bqueue.put q (line ^ "\r\n");
                go (size + String.length line + 2)
        in
        let relay's_result = go 0 in
        let user's_result = Miou.Computation.await_exn oc in
        let v = merge relay's_result user's_result in
        let t = SMTP.m_end v ctx in
        let* `Quit = run Msendmail.tcp flow t in
        let* () = properly_close_starttls ctx flow in
        begin match v with `Ok -> Ok () | #user's_error as err -> Error err
        end
    | `Send _ ->
        assert (Miou.Computation.try_cancel ic recipients_unreachable);
        let msg = "No valid recipients" in
        let t = SMTP.m_properly_close_and_fail ctx msg in
        run Msendmail.tcp flow t
end

module Submission = struct
  type ic = (string * email) Miou.Computation.t

  type error =
    [ user's_error
    | `Invalid_recipients
    | `No_recipients
    | `Too_many_bad_commands
    | `Too_many_recipients
    | `Protocol of SSMTP.Value.error ]

  type authenticator = ?payload:string -> Mechanism.t -> string * bool
  type authentication = Mechanism.t list * authenticator

  let authentication ctx ~info (ms, authentication) flow =
    let rec go retries ~domain_from ?payload mechanism =
      if retries <= 0 then assert false
      else
        match authentication ?payload mechanism with
        | username, true ->
            let msg = [ "Accepted, buddy!" ] in
            let t = SSMTP.(Monad.send ctx Value.PP_235 msg) in
            let* () = run Msendmail.tls flow t in
            Ok (`Authenticated (domain_from, username))
        | _, false -> begin
            let t =
              let open SSMTP in
              let open Monad in
              let msg = [ "Bad authentication, buddy!" ] in
              let* () = send ctx Value.PN_535 msg in
              m_submission ctx ~domain_from ms
            in
            let* operation = run Msendmail.tls flow t in
            match operation with
            | `Quit -> Ok `Quit
            | `Authentication (domain_from, mechanism) ->
                go (retries - 1) ~domain_from mechanism
            | `Authentication_with_payload (domain_from, mechanism, payload) ->
                go (retries - 1) ~domain_from ~payload mechanism
          end
    in
    let t = SSMTP.m_submission_init ctx info ms in
    let* operation = run Msendmail.tls flow t in
    match operation with
    | `Quit -> Ok `Quit
    | `Authentication (domain_from, mechanism) -> go 3 ~domain_from mechanism
    | `Authentication_with_payload (domain_from, mechanism, payload) ->
        go 3 ~domain_from ~payload mechanism

  let handler ?encoder ?decoder ~info dns auth flow (ic, oc) q =
    let ctx = Colombe.State.Context.make ?encoder ?decoder () in
    let* operation = authentication ctx ~info auth flow in
    match operation with
    | `Quit -> Ok ()
    | `Authenticated (domain_from, username) -> begin
        let t = SSMTP.m_relay ctx ~domain_from in
        let* operation = run Msendmail.tls flow t in
        match operation with
        | `Quit -> Ok ()
        | `Send ({ SMTP.recipients; _ } as m)
          when recipients_are_reachable ~info dns (List.map fst recipients) ->
            assert (Miou.Computation.try_return ic (username, m));
            let t = SSMTP.m_mail ctx in
            let* () = run Msendmail.tls flow t in
            let rec go size =
              if size > info.size then begin
                Flux.Bqueue.close q; Error `Too_big_data
              end
              else
                let t = SSMTP.(Monad.recv ctx Value.Payload) in
                let result = run Msendmail.tls flow t in
                match result with
                | Ok ".." ->
                    Flux.Bqueue.put q ".\r\n";
                    go (size + 3)
                | Ok "." -> Flux.Bqueue.close q; Ok ()
                | Error _ as err -> Flux.Bqueue.close q; err
                | Ok line ->
                    Flux.Bqueue.put q (line ^ "\r\n");
                    go (size + String.length line + 2)
            in
            let relay's_result = go 0 in
            let user's_result = Miou.Computation.await_exn oc in
            let v = merge relay's_result user's_result in
            let t = SSMTP.m_end v ctx in
            let* `Quit = run Msendmail.tls flow t in
            begin match v with
            | `Ok -> Ok ()
            | #user's_error as err -> Error err
            end
        | `Send _ ->
            assert (Miou.Computation.try_cancel ic recipients_unreachable);
            let msg = "No valid recipients" in
            let t = SSMTP.m_properly_close_and_fail ctx msg in
            run Msendmail.tls flow t
      end
end
