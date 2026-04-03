let src = Logs.Src.create "facteur"

module Log = (val Logs.src_log src : Logs.LOG)
module Aggregate = Aggregate

type info = { domain: Colombe.Domain.t; tls: Tls.Config.client option }

(*
type email =
  { from : Reverse_path.t
  ; recipients : Forward_path.t list
  ; destination : string
  ; stream : string Flux.Stream.t }
*)

type buffers = bytes * bytes * (char, Bigarray.int8_unsigned_elt) Ke.Rke.t
type t = { he: Mnet_happy_eyeballs.t; pool: buffers Cattery.t }

let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Key = struct
  type t = Dns.Mx.t

  let compare { Dns.Mx.preference= a; _ } { Dns.Mx.preference= b; _ } =
    Int.compare a b
end

module Mxs = Map.Make (Key)

let mxs (Ptt.Resolver { dns; getmxbyname; gethostbyname }) = function
  | `Ipaddr ipaddr ->
      let mail_exchange = Ipaddr.to_domain_name ipaddr in
      let key = { Dns.Mx.preference= 0; mail_exchange } in
      Ok (Mxs.singleton key [ ipaddr ])
  | `Domain domain_name ->
      let* mxs = getmxbyname dns domain_name in
      let mxs = Dns.Rr_map.Mx_set.to_list mxs in
      let fn acc ({ Dns.Mx.mail_exchange; _ } as key) =
        match gethostbyname dns mail_exchange with
        | Ok ipaddrs -> Mxs.add key ipaddrs acc
        | Error _ -> acc
      in
      let mxs = List.fold_left fn Mxs.empty mxs in
      if Mxs.is_empty mxs then
        error_msgf "No SMTP server affiliated to %a" Domain_name.pp domain_name
      else Ok mxs

let sendmail t info resolver (from, ({ Aggregate.domain; locals } as a)) seq =
  Cattery.use t.pool @@ fun (decoder, encoder, queue) ->
  let encoder = Fun.const encoder
  and decoder = Fun.const decoder
  and queue = Fun.const queue
  and recipients =
    let open Colombe in
    let open Forward_path in
    let domain =
      match domain with
      | `Ipaddr (Ipaddr.V4 v4) -> Domain.IPv4 v4
      | `Ipaddr (Ipaddr.V6 v6) -> Domain.IPv6 v6
      | `Domain v -> Domain.Domain (Domain_name.to_strings v)
    in
    let local_to_forward_path local =
      let local = List.map (function `Atom x -> x | `String x -> x) local in
      Forward_path { Path.local= `Dot_string local; domain; rest= [] }
    in
    match locals with
    | `All -> [ Domain domain ]
    | `Some locals -> List.map local_to_forward_path locals
    | `Postmaster -> [ Postmaster ]
  in
  let* mxs = mxs resolver domain in
  let mxs = Mxs.bindings mxs in
  let rec go seq mxs =
    match (mxs, Seq.uncons seq) with
    | [], _ -> assert false
    | _, None ->
        invalid_arg
          "Facteur.sendmail: the given sequence must be a Seq.forever sequence"
    | [ (_mx, ipaddrs) ], Some (stream, _) ->
        let destination = `Ips ipaddrs in
        let fn str = (str, 0, String.length str) in
        let stream = Flux.Stream.map fn stream in
        Msendmail.sendmail ~encoder ~decoder ~queue t.he ~destination
          ~domain:info.domain ?cfg:info.tls from recipients stream
    | (_mx, ipaddrs) :: mxs, Some (stream, seq) -> begin
        let destination = `Ips ipaddrs in
        let fn str = (str, 0, String.length str) in
        let stream = Flux.Stream.map fn stream in
        let result =
          Msendmail.sendmail ~encoder ~decoder ~queue t.he ~destination
            ~domain:info.domain ?cfg:info.tls from recipients stream
        in
        match result with
        | Ok _ as value ->
            Log.debug (fun m -> m "Email sent to %a" Aggregate.pp a);
            value
        | Error err ->
            Log.warn (fun m ->
                m "Impossible to send an email to %a (%a): %a" Aggregate.pp a
                  Fmt.(list ~sep:(any ",") Ipaddr.pp)
                  ipaddrs Msendmail.pp_error err);
            go seq mxs
      end
  in
  go seq mxs

type error = [ `Msg of string | Sendmail_with_starttls.error ]

let pp_error ppf = function
  | #Sendmail_with_starttls.error as err ->
      Sendmail_with_starttls.pp_error ppf err
  | `Msg msg -> Fmt.string ppf msg

let domain_of_forward_path = function
  | Colombe.Forward_path.Forward_path { Colombe.Path.domain; _ } -> Some domain
  | Colombe.Forward_path.Domain domain -> Some domain
  | Colombe.Forward_path.Postmaster -> None

let destination_of_domain = function
  | Colombe.Domain.Domain vs ->
      let* v = Domain_name.of_strings vs in
      let* v = Domain_name.host v in
      Ok (`Domain v)
  | Colombe.Domain.IPv4 v4 -> Ok (`Ipaddr (Ipaddr.V4 v4))
  | Colombe.Domain.IPv6 v6 -> Ok (`Ipaddr (Ipaddr.V6 v6))
  | Colombe.Domain.Extension (k, v) ->
      error_msgf "Unsupported domain extension: [%s:%s]" k v

let many t ~info resolver ~destination:domain txs seq =
  if txs = [] then invalid_arg "Facteur.many: txs must not be empty";
  let check_domain (_from, rcpt) =
    match domain_of_forward_path rcpt with
    | Some domain' when Colombe.Domain.equal domain domain' -> ()
    | Some domain ->
        Fmt.invalid_arg
          "Facteur.many: recipient domain %a does not match destination %a"
          Colombe.Domain.pp domain Colombe.Domain.pp domain
    | None -> ()
  in
  List.iter check_domain txs;
  Cattery.use t.pool @@ fun (decoder, encoder, queue) ->
  let encoder = Fun.const encoder
  and decoder = Fun.const decoder
  and queue = Fun.const queue in
  let* destination = destination_of_domain domain in
  let* mxs = mxs resolver destination in
  Log.debug (fun m ->
      m "Try to send %d email(s) to %d Mail-eXchange server(s)"
        (List.length txs) (Mxs.cardinal mxs));
  let mxs = Mxs.bindings mxs in
  let fn stream =
    let fn str = (str, 0, String.length str) in
    Flux.Stream.map fn stream
  in
  let seq = Seq.map fn seq in
  let rec go mxs =
    match mxs with
    | [] -> assert false
    | [ (_mx, ipaddrs) ] ->
        Log.debug (fun m ->
            m "Communication with %a"
              Fmt.(list ~sep:(any ",") Ipaddr.pp)
              ipaddrs);
        let dst = `Ips ipaddrs in
        let* results =
          Msendmail.many ~encoder ~decoder ~queue t.he ~destination:dst
            ~domain:info.domain ?cfg:info.tls txs seq
        in
        let fn (rp, fp, result) =
          let fn err = (err :> error) in
          let result = Result.map_error fn result in
          (rp, fp, result)
        in
        Ok (List.map fn results)
    | (_mx, ipaddrs) :: mxs -> begin
        Log.debug (fun m ->
            m "Communication with %a"
              Fmt.(list ~sep:(any ",") Ipaddr.pp)
              ipaddrs);
        let dst = `Ips ipaddrs in
        let result =
          Msendmail.many ~encoder ~decoder ~queue t.he ~destination:dst
            ~domain:info.domain ?cfg:info.tls txs seq
        in
        match result with
        | Ok results ->
            let fn (rp, fp, result) =
              let fn err = (err :> error) in
              let result = Result.map_error fn result in
              (rp, fp, result)
            in
            Ok (List.map fn results)
        | Error err ->
            Log.warn (fun m ->
                m "Impossible to send an email to %a (%a): %a" Colombe.Domain.pp
                  domain
                  Fmt.(list ~sep:(any ",") Ipaddr.pp)
                  ipaddrs Msendmail.pp_error err);
            go mxs
      end
  in
  go mxs

module By_domain = Map.Make (Colombe.Domain)

(* TODO(dinosaure): multiple [from] and multiple [recipients]. *)
let broadcast t ~info resolver txs seq =
  if txs = [] then invalid_arg "Facteur.broadcast: recipients must not be empty";
  let by_domain =
    let fn acc (sender, rcpt) =
      match domain_of_forward_path rcpt with
      | Some domain ->
          let vs = By_domain.find_opt domain acc in
          let vs = Option.value ~default:[] vs in
          By_domain.add domain ((sender, rcpt) :: vs) acc
      | None -> acc
    in
    List.fold_left fn By_domain.empty txs
  in
  let groups = By_domain.bindings by_domain in
  let prms =
    let fn (destination, txs) =
      Miou.async @@ fun () ->
      (destination, many t ~info resolver ~destination txs seq)
    in
    List.map fn groups
  in
  let results = Miou.await_all prms in
  let fn = function
    | Error _exn -> []
    | Ok (_, Error _err) -> []
    | Ok (destination, Ok results) ->
        let fn (rp, fp, result) = (destination, rp, fp, result) in
        List.map fn results
  in
  List.map fn results |> List.flatten

let sendmail t ~info resolver ~from recipients seq =
  if recipients = [] then
    invalid_arg "Facteur.sendmail: recipients must not be empty";
  let recipients = Aggregate.to_recipients ~domain:info.domain recipients in
  Log.debug (fun m ->
      m "send email to: %a" Fmt.(list ~sep:(any ",") Aggregate.pp) recipients);
  let fn recipients =
    Miou.async @@ fun () ->
    let result = sendmail t info resolver (from, recipients) seq in
    (recipients, result)
  in
  let prms = List.map fn recipients in
  let results = Miou.await_all prms in
  let fn = function
    | Ok (recipients, Ok ()) ->
        Log.debug (fun m -> m "Email sent to %a" Aggregate.pp recipients);
        None
    | Ok (recipients, Error err) ->
        Log.err (fun m ->
            m "Impossible to send an email to %a: %a" Aggregate.pp recipients
              Msendmail.pp_error err);
        Some (recipients, err)
    | Error exn ->
        Log.err (fun m -> m "Got an exception: %s" (Printexc.to_string exn));
        None
  in
  List.filter_map fn results
