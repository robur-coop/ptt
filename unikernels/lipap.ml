module Blk = struct
  type t = Mkernel.Block.t

  let pagesize = Mkernel.Block.pagesize
  let read = Mkernel.Block.atomic_read
  let write = Mkernel.Block.atomic_write
end

module Fat = Mfat.Make (Blk)
module RNG = Mirage_crypto_rng.Fortuna
module S = Map.Make (String)
open Utils

let ( let@ ) finally fn = Fun.protect ~finally fn
let ( let* ) = Result.bind
let ( / ) = Filename.concat
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let msg str = `Msg str
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

exception Handler_failed

let handler_failed =
  let bt = Printexc.get_callstack 0 in
  (Handler_failed, bt)

type value = {
    encoder: bytes
  ; decoder: bytes
  ; queue: (char, Bigarray.int8_unsigned_elt) Ke.Rke.t
  ; contents: Bstr.t
}

type cfg = {
    forward: Ipaddr.t -> bool
  ; pool: value Cattery.t
  ; dns: Mnet_dns.t
  ; client: Facteur.t
  ; mutable lists: Mlm.t S.t
  ; bounces: Bounces.t
  ; to_arc: Ipaddr.t
  ; to_dkim: Ipaddr.t
  ; admin: (Emile.local option * Colombe.Forward_path.t) option
}

let is_us domain info = Colombe.Domain.equal domain info.Ptt.domain

let is_for_an_existing_mailing_list fp info cfg =
  match fp with
  | Colombe.Forward_path.Postmaster -> None
  | Domain _ -> None
  | Forward_path ({ local; domain; rest= [] } as path) when is_us domain info ->
      let local = Colombe.Path.Encoder.local_to_string local in
      let local = List.hd (String.split_on_char '-' local) in
      let fn list = (list, path) in
      Option.map fn (S.find_opt local cfg.lists)
  | _ -> None

let is_admin fp info cfg =
  match (cfg.admin, fp) with
  | None, _ -> None
  | Some (_, rcpt), Colombe.Forward_path.Postmaster -> Some rcpt
  | Some (_, rcpt), Domain domain when is_us domain info -> Some rcpt
  | Some (Some local', rcpt), Forward_path { local; domain; rest= [] } ->
      let local = Colombe_emile.of_local local in
      if is_us domain info && Emile.equal_local local local' then Some rcpt
      else None
  | _ -> None

module Incoming = struct
  let aresults ~receiver ppf =
    let open Prettym in
    eval ppf
      [
        string $ "Authentication-Results"; char $ ':'; spaces 1
      ; !!(Dmarc.Encoder.field ~receiver)
      ]

  let last_arc_set hdrs =
    let is_arc_seal =
      let open Mrmime.Field_name in
      equal (v "ARC-Seal")
    in
    let get_arc_signature unstrctrd =
      let* m = Dkim.of_unstrctrd_to_map unstrctrd in
      let none = msgf "Missing i ARC field" in
      let* i = Option.to_result ~none (Dkim.get_key "i" m) in
      let none = msgf "Invalid unique ARC ID value" in
      let* i = Option.to_result ~none (int_of_string_opt i) in
      let* t = Dkim.map_to_t m in
      Ok (i, t, m)
    in
    let rec go uid = function
      | (field_name, unstrctrd) :: hdrs ->
          if is_arc_seal field_name then
            match get_arc_signature unstrctrd with
            | Ok (uid', _, _) -> go (Int.max uid uid') hdrs
            | Error _ -> go uid hdrs
          else go uid hdrs
      | [] -> uid
    in
    go 0 hdrs

  let receiver ~info =
    match info.Ptt.domain with
    | Colombe.Domain.Domain ds -> `Domain ds
    | IPv4 ipv4 -> `Addr (Emile.IPv4 ipv4)
    | IPv6 ipv6 -> `Addr (Emile.IPv6 ipv6)
    | Extension (k, v) -> `Addr (Emile.Ext (k, v))

  let static destination =
    let gethostbyname ipaddrs _ = Result.ok ipaddrs
    and getmxbyname _ mail_exchange =
      Ok (Dns.Rr_map.Mx_set.singleton { preference= 0; mail_exchange })
    in
    Ptt.Resolver { gethostbyname; getmxbyname; dns= [ destination ] }

  let send_locally client ~info ?aresults lst ipaddr outgoing =
    let resolver = static ipaddr in
    let fn lst { Mlm.sender; recipients; seq } =
      let with_aresults stream =
        match aresults with
        | None -> stream
        | Some aresults ->
            let aresults = Flux.Source.list [ aresults ] in
            let aresults = Flux.Stream.from aresults in
            Flux.Stream.concat aresults stream
      in
      let seq = Seq.map with_aresults seq in
      let from = sender and rcpts = recipients in
      let errs = Facteur.sendmail client ~info resolver ~from rcpts seq in
      let fn (a, err) =
        Logs.err (fun m ->
            m "Impossible to send an email to %a: %a" Facteur.Aggregate.pp a
              Facteur.pp_error err)
      in
      List.iter fn errs; lst
    in
    List.fold_left fn lst outgoing

  let handler ~cfg ~info:(sinfo, cinfo) peer m oc q v =
    (* Here, we analyse the email (SPF, DKIM and DMARC validation) and then let
       our [Mlm] module handle the email according to the mailing lists. In all
       cases, an {ARC-,}Authentication-Results header is added.

       The mailing list logic may need to send emails to our ARC signer (this is
       the case when acting as a relay) or to our DKIM signer (when the mailing
       list wants to create and send a new email). More generally, incoming
       emails are only intended for our local network.

       If we are unable to parse the email or properly verify SPF, DKIM and
       DMARC, we simply ignore the email. *)
    Logs.debug (fun m -> m "Analyze incoming emails from Internet");
    assert (Miou.Computation.try_return oc `Ok);
    let src = Flux.Source.bqueue q in
    let stream = Flux.Stream.from src in
    let from = fst m.Ptt.from in
    let rcpts, to_lists =
      let fn (fp, _) =
        match is_admin fp sinfo cfg with
        | None ->
            Option.map Either.right
              (is_for_an_existing_mailing_list fp sinfo cfg)
        | Some admin -> Some (Either.Left admin)
      in
      let rcpts = List.filter_map fn m.Ptt.recipients in
      List.partition_map Fun.id rcpts
    in
    if List.is_empty rcpts = false || List.is_empty to_lists = false then begin
      let ctx = Uspf.empty in
      let ctx = Uspf.with_ip peer ctx in
      let ctx =
        let some v = Uspf.with_sender (`MAILFROM v) ctx in
        Option.fold ~none:ctx ~some from
      in
      let into =
        let open Flux.Sink.Syntax in
        let+ bstr = save_into v.contents
        and+ dmarc = dmarc ~ctx cfg.dns
        and+ hdrs = headers in
        (bstr, hdrs, dmarc)
      in
      Logs.debug (fun m -> m "Consume incoming email");
      let bstr, hdrs, dmarc = Flux.Stream.into into stream in
      Logs.debug (fun m ->
          let hash = Digestif.SHA256.digest_bigstring bstr in
          m "Incoming email: %a" Digestif.SHA256.pp hash);
      let with_list (arc_aresults, aresults) (lst, rcpt) =
        match Mlm.incoming lst cfg.bounces ~from ~rcpt bstr with
        | Ok (lst', outgoing0, outgoing1) ->
            let info = cinfo in
            let client = cfg.client in
            let dst = cfg.to_dkim in
            let lst' = send_locally client ~info ~aresults lst' dst outgoing1 in
            let dst = cfg.to_arc in
            let aresults = arc_aresults in
            let lst' = send_locally client ~info ~aresults lst' dst outgoing0 in
            cfg.lists <- S.add (Mlm.name lst') lst' cfg.lists
        | Error (`Msg msg) ->
            Logs.err (fun m ->
                m "Error during processing incoming email: %s" msg)
      in
      let for_admin arc_aresults rcpt =
        let seq =
          Seq.forever @@ fun () ->
          let arc_aresults = Flux.Source.list [ arc_aresults ] in
          let arc_aresults = Flux.Stream.from arc_aresults in
          let stream = Flux.Stream.from (from_bstr bstr) in
          Flux.Stream.concat arc_aresults stream
        in
        let from = fst m.Ptt.from
        and rcpts = [ rcpt ]
        and info = cinfo
        and client = cfg.client
        and resolver = static cfg.to_arc in
        let _errs = Facteur.sendmail client ~info resolver ~from rcpts seq in
        ()
      in
      begin match (hdrs, dmarc) with
      | Ok hdrs, Ok dmarc ->
          let receiver = receiver ~info:sinfo in
          let arc_authentication_results =
            let uid = succ (last_arc_set hdrs) in
            let encoder = Arc.Encoder.stamp_results ~receiver ~uid in
            Prettym.to_string ~new_line:"\r\n" encoder dmarc
          in
          let authentication_results =
            let encoder = aresults ~receiver in
            Prettym.to_string ~new_line:"\r\n" encoder dmarc
          in
          let aresults = (arc_authentication_results, authentication_results) in
          List.iter (with_list aresults) to_lists;
          List.iter (for_admin arc_authentication_results) rcpts
      | _, Error err -> Logs.err (fun m -> m "DMARC error: %a" pp_error err)
      | Error err, _ ->
          Logs.err (fun m -> m "Invalid incoming email: %a" pp_error err)
      end
    end
end

module Outgoing = struct
  let broadcast cfg client ~info resolver _lst ~counter txs seq =
    let fn { Mlm.sender; recipient } = (sender, recipient) in
    let txs = List.map fn txs in
    let results = Facteur.broadcast client ~info resolver txs seq in
    let fn (_domain, fp, result) =
      match (result, fp) with
      | Error err, Colombe.Forward_path.Forward_path fp ->
          Logs.err (fun m ->
              m "Impossible to send an email to %a: %a" Colombe.Path.pp fp
                Facteur.pp_error err);
          Bounces.failure_for cfg.bounces ~counter fp
      | Ok (), Colombe.Forward_path.Forward_path fp ->
          Bounces.success_for cfg.bounces ~counter fp;
          None
      | _ -> None
    in
    let _to_delete = List.filter_map fn results in
    ()

  let handler ~cfg ~info:(sinfo, cinfo) resolver m oc q v =
    assert (Miou.Computation.try_return oc `Ok);
    let from = Flux.Source.bqueue q in
    let stream = Flux.Stream.from from in
    let mrcpts, rcpts =
      let fn (fp, _) =
        match is_for_an_existing_mailing_list fp sinfo cfg with
        | Some (lst, fp) -> Either.Left (lst, fp)
        | None -> Either.Right fp
      in
      List.partition_map fn m.Ptt.recipients
    in
    let bstr = Flux.Stream.into (save_into v.contents) stream in
    let seq = Seq.forever @@ fun () -> Flux.Stream.from (from_bstr bstr) in
    let from = fst m.Ptt.from in
    let fn (lst, rcpt) =
      match Mlm.outgoing lst ~from ~rcpt with
      | Ok (lst', counter, txs) ->
          let info = cinfo in
          let client = cfg.client in
          broadcast cfg client ~info resolver lst' ~counter txs seq
      | Error (`Msg msg) ->
          Logs.err (fun m ->
              m "Error during processing incoming email (local network): %s" msg)
    in
    List.iter fn mrcpts;
    let info = cinfo in
    let client = cfg.client in
    let fn rcpt = (fst m.Ptt.from, rcpt) in
    let txs = List.map fn rcpts in
    let errs = Facteur.broadcast client ~info resolver txs seq in
    let fn (_domain, fp, result) =
      match result with
      | Ok () -> ()
      | Error err ->
          Logs.err (fun m ->
              m "Impossible to send an email to %a: %a" Colombe.Forward_path.pp
                fp Facteur.pp_error err)
    in
    List.iter fn errs
end

let resolver_according_to_peer ~cfg static flow =
  let _, (peer, _) = Mnet.TCP.peers flow in
  match cfg.forward peer with
  | true ->
      let dns = cfg.dns in
      let gethostbyname dns domain_name =
        let ipv4 = Mnet_dns.gethostbyname dns domain_name in
        let ipv6 = Mnet_dns.gethostbyname6 dns domain_name in
        match (ipv4, ipv6) with
        | Ok ipv4, Ok ipv6 -> Ok [ Ipaddr.V4 ipv4; Ipaddr.V6 ipv6 ]
        | Ok ipv4, Error _ -> Ok [ Ipaddr.V4 ipv4 ]
        | Error _, Ok ipv6 -> Ok [ Ipaddr.V6 ipv6 ]
        | (Error _ as err), _ -> err
      in
      let getmxbyname dns domain_name =
        let* _ttl, mxs = Mnet_dns.getaddrinfo dns Dns.Rr_map.Mx domain_name in
        Ok mxs
      in
      Ptt.Resolver { gethostbyname; getmxbyname; dns }
  | false ->
      let gethostbyname ipaddrs _ = Result.ok ipaddrs
      and getmxbyname _ mail_exchange =
        Ok (Dns.Rr_map.Mx_set.singleton { preference= 0; mail_exchange })
      in
      Ptt.Resolver { gethostbyname; getmxbyname; dns= [ static ] }

let to_forward ~cfg flow =
  let _, (peer, _) = Mnet.TCP.peers flow in
  cfg.forward peer

let handler ~cfg ~info:((sinfo, _) as info) flow =
  Cattery.use cfg.pool @@ fun v ->
  let forward = to_forward ~cfg flow in
  (* NOTE(dinosaure): here, we use [to_arc] but we can also use [to_dkim]
     but it does not really matter. *)
  let resolver = resolver_according_to_peer ~cfg cfg.to_arc flow in
  let _, (peer, port) = Mnet.TCP.peers flow in
  let ic = Miou.Computation.create () in
  let oc = Miou.Computation.create () in
  let q = Flux.Bqueue.(create with_close) 0x7ff in
  let prm0 =
    Miou.async @@ fun () ->
    let finally ic = assert (Miou.Computation.try_cancel ic handler_failed) in
    let resource = Miou.Ownership.create ~finally ic in
    Miou.Ownership.own resource;
    let encoder = Fun.const v.encoder
    and decoder = Fun.const v.decoder
    and queue = Fun.const v.queue in
    match
      Ptt.Relay.handler ~encoder ~decoder ~queue ~info:sinfo resolver flow
        (ic, oc) q
    with
    | Ok () ->
        Logs.debug (fun m -> m "%a:%d terminated" Ipaddr.pp peer port);
        Miou.Ownership.disown resource
    | Error err ->
        Miou.Ownership.release resource;
        Logs.err (fun m ->
            m "%a:%d finished with an error: %a" Ipaddr.pp peer port
              Ptt.Relay.pp_error err)
  in
  let prm1 =
    Miou.async @@ fun () ->
    match Miou.Computation.await_exn ic with
    | m when forward -> Outgoing.handler ~cfg ~info resolver m oc q v
    | m -> Incoming.handler ~cfg ~info peer m oc q v
    | exception Ptt.Recipients_unreachable ->
        Logs.err (fun m -> m "Given recipients are unreachable")
    | exception Ptt.Quit ->
        Logs.debug (fun m ->
            m "%a:%d without any operations" Ipaddr.pp peer port)
    | exception Handler_failed -> Logs.err (fun m -> m "Relay handler failed")
  in
  let _ = Miou.await prm0 in
  let () = Miou.await_exn prm1 in
  Mnet.TCP.close flow

let rec clean_up orphans =
  match Miou.care orphans with
  | Some None | None -> ()
  | Some (Some prm) ->
      let _ = Miou.await prm in
      clean_up orphans

let _5s = 5_000_000_000

let expired certs =
  let fn than cert =
    let _, not_after = X509.Certificate.validity cert in
    if Ptime.is_earlier not_after ~than then not_after else than
  in
  let now = Mirage_ptime.now () in
  let not_after = List.fold_left fn now certs in
  Ptime.is_earlier not_after ~than:now

let not_expired = Fun.negate expired

let server ~cfg ~info tcp dns_key ~hostname ~key_seed (dns_ip, dns_port) =
  (* This code is primarily used to request and obtain a TLS certificate from
     our primary DNS server. It manages the certificate’s expiry. Client
     management is never interrupted, even during a renegotiation. We allow five
     seconds before the certificate actually expires to initiate the new
     renegotiation. *)
  let listen = Mnet.TCP.listen tcp 25 in
  let mutex = Miou.Mutex.create () in
  let condition = Miou.Condition.create () in
  let shared = Queue.create () in
  let rec filler () =
    let flow = Mnet.TCP.accept tcp listen in
    let () =
      Miou.Mutex.protect mutex @@ fun () ->
      Queue.push flow shared;
      Miou.Condition.signal condition
    in
    filler ()
  in
  let rec go orphans =
    match
      Cert.retrieve_certificate tcp dns_key ~hostname ~key_seed dns_ip dns_port
    with
    | Error (`Msg msg) ->
        Fmt.failwith "Impossible to retrieve TLS certificate: %s" msg
    | Error _ -> Fmt.failwith "Impossible to retrieve TLS certificate"
    | Ok (certs, key) ->
        let not_after = snd (X509.Certificate.validity (List.hd certs)) in
        Logs.info (fun m ->
            m "Certificate retrieved, valid until %a" Ptime.pp not_after);
        let tls = Tls.Config.server ~certificates:(`Single (certs, key)) () in
        let tls = Result.get_ok tls in
        let info = ({ (fst info) with Ptt.tls= Some tls }, snd info) in
        let handler = handler ~cfg ~info in
        let server = Miou.async @@ fun () -> filler () in
        let signal =
          Miou.async @@ fun () ->
          let now = Mirage_ptime.now () in
          let remaining = Ptime.diff not_after now in
          let secs = Ptime.Span.to_int_s remaining |> Option.value ~default:0 in
          let nsec = secs * 1_000_000_000 in
          let v = Int.max 0 (nsec - _5s) in
          Logs.debug (fun m -> m "Wait %a" Duration.pp (Int64.of_int v));
          Mkernel.sleep v;
          Miou.Mutex.protect mutex @@ fun () -> Miou.Condition.signal condition
        in
        let rec until_expiration orphans =
          clean_up orphans;
          let state =
            Miou.Mutex.protect mutex @@ fun () ->
            while Queue.is_empty shared && not_expired certs do
              Miou.Condition.wait condition mutex
            done;
            if expired certs then `Expired
            else begin
              let flows = List.of_seq (Queue.to_seq shared) in
              Queue.clear shared; `Clients flows
            end
          in
          match state with
          | `Expired ->
              Logs.info (fun m -> m "Certificate expiring, renewing...");
              Miou.await_exn signal;
              Miou.cancel server
          | `Clients flows ->
              let fn flow =
                let _, (peer, port) = Mnet.TCP.peers flow in
                Logs.debug (fun m ->
                    m "Got a new connection from %a:%d" Ipaddr.pp peer port);
                ignore (Miou.async ~orphans @@ fun () -> handler flow)
              in
              List.iter fn flows; until_expiration orphans
        in
        until_expiration orphans; go orphans
  in
  go (Miou.orphans ())

let fat ~name =
  let fn blk () =
    let v = Fat.create blk in
    let v = Result.map_error (fun (`Msg msg) -> msg) v in
    Result.error_to_failure v
  in
  Mkernel.map fn [ Mkernel.block name ]

let lists ~info fs =
  let* entries = Fat.ls fs "lists" in
  Logs.debug (fun m -> m "%d possible mailing lists" (List.length entries));
  let fn acc = function
    | { Mfat.is_dir= true; _ } -> acc
    | { Mfat.name= filepath; _ } ->
        let name = Filename.chop_extension filepath in
        let result =
          let* name = Mlm.local_of_string name in
          let name = Colombe_emile.of_local name in
          let* contents = Fat.read fs ("lists" / filepath) in
          let rec jsont = lazy (Mlm.json ~store ~domain:info.Ptt.domain name)
          and store t =
            let str = Jsont_bytesrw.encode_string (Lazy.force jsont) t in
            let str = Result.get_ok str in
            let process () =
              (* TODO(dinosaure): should be an atomic operation (power failure). *)
              let* () = Fat.remove fs ("lists" / filepath) in
              Fat.write fs ("lists" / filepath) str
            in
            match process () with
            | Ok () -> ()
            | Error (`Msg msg) ->
                Logs.err (fun m ->
                    m "Error during saving a new state for %a: %s"
                      Emile.pp_mailbox (Mlm.to_emile t) msg)
          in
          let jsont = Lazy.force jsont in
          Jsont_bytesrw.decode_string jsont contents |> Result.map_error msg
        in
        begin match result with
        | Ok t ->
            Logs.debug (fun m -> m "Add %s as a mailing list" name);
            S.add name t acc
        | Error (`Msg msg) ->
            Logs.warn (fun m -> m "Invalid mailing list %s: %s" name msg);
            acc
        end
  in
  let m = List.fold_left fn S.empty entries in
  Ok m

let run _ (cidrv4, gateway, ipv6) info nameservers forward_granted_for to_arc
    to_dkim cert admin =
  let hostname, cert_dns, dns_key, key_seed = cert in
  let devices =
    let open Mkernel in
    [ rng; Mnet.stack ~name:"service" ?gateway ~ipv6 cidrv4; fat ~name:"lipap" ]
  in
  Mkernel.run devices @@ fun rng (stack, tcp, udp) fs () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill stack in
  let hed, he = Mnet_happy_eyeballs.create tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let dns = Mnet_dns.create ~nameservers (udp, he) in
  let t = Mnet_dns.transport dns in
  let@ () = fun () -> Mnet_dns.Transport.kill t in
  let sinfo = fst info in
  let pool =
    Cattery.create 16 @@ fun () ->
    let encoder = Bytes.create 4096 in
    let decoder = Bytes.create 4096 in
    let queue = Ke.Rke.create Bigarray.char ~capacity:0x1000 in
    let contents = Bstr.create sinfo.Ptt.size in
    { encoder; decoder; queue; contents }
  in
  let client =
    let pool =
      Cattery.create 16 @@ fun () ->
      let encoder = Bytes.create 4096 in
      let decoder = Bytes.create 4096 in
      let queue = Ke.Rke.create Bigarray.char ~capacity:0x1000 in
      (encoder, decoder, queue)
    in
    { Facteur.he; pool }
  in
  let lists =
    match lists ~info:sinfo fs with
    | Ok value -> value
    | Error (`Msg msg) as err ->
        Logs.err (fun m -> m "Impossible to read our state: %s" msg);
        S.empty
  in
  let forward ipaddr =
    let fn = Ipaddr.Prefix.mem ipaddr in
    List.exists fn forward_granted_for
  in
  let bounces =
    let rec jsont = lazy (Bounces.json ~store ())
    and store t =
      let str = Jsont_bytesrw.encode_string (Lazy.force jsont) t in
      let str = Result.get_ok str in
      let process () =
        (* TODO(dinosaure): should be an atomic operation (power failure). *)
        let _ = Fat.remove fs "bounces.json" in
        Fat.write fs "bounces.json" str
      in
      match process () with
      | Ok () -> ()
      | Error (`Msg msg) ->
          Logs.err (fun m -> m "Error during saving bounces state: %s" msg)
    in
    let process () =
      let* contents = Fat.read fs "bounces.json" in
      let jsont = Lazy.force jsont in
      Jsont_bytesrw.decode_string jsont contents |> Result.map_error msg
    in
    match process () with
    | Ok bounces -> bounces
    | _ -> Bounces.create ~store ()
  in
  let cfg =
    { forward; pool; dns; client; lists; bounces; to_arc; to_dkim; admin }
  in
  server ~cfg ~info tcp dns_key ~hostname ~key_seed cert_dns

open Cmdliner

let output_options = "OUTPUT OPTIONS"
let verbosity = Logs_cli.level ~docs:output_options ()
let renderer = Fmt_cli.style_renderer ~docs:output_options ()

let utf_8 =
  let doc = "Allow binaries to emit UTF-8 characters." in
  Arg.(value & opt bool true & info [ "with-utf-8" ] ~doc)

let t0 = Mkernel.clock_monotonic ()
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let neg fn = fun x -> not (fn x)

let reporter sources ppf =
  let re = Option.map Re.compile sources in
  let print src =
    let some re = (neg List.is_empty) (Re.matches re (Logs.Src.name src)) in
    Option.fold ~none:true ~some re
  in
  let report src level ~over k msgf =
    let k _ = over (); k () in
    let pp header _tags k ppf fmt =
      let t1 = Mkernel.clock_monotonic () in
      let delta = Float.of_int (t1 - t0) in
      let delta = delta /. 1_000_000_000. in
      Fmt.kpf k ppf
        ("[+%a][%a]%a[%a]: " ^^ fmt ^^ "\n%!")
        Fmt.(styled `Blue (fmt "%04.04f"))
        delta
        Fmt.(styled `Cyan int)
        (Stdlib.Domain.self () :> int)
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src)
    in
    match (level, print src) with
    | Logs.Debug, false -> k ()
    | _, true | _ -> msgf @@ fun ?header ?tags fmt -> pp header tags k ppf fmt
  in
  { Logs.report }

let regexp =
  let parser str =
    match Re.Pcre.re str with
    | re -> Ok (str, `Re re)
    | exception _ -> error_msgf "Invalid PCRegexp: %S" str
  in
  let pp ppf (str, _) = Fmt.string ppf str in
  Arg.conv (parser, pp)

let sources =
  let doc = "A regexp (PCRE syntax) to identify which log we print." in
  let open Arg in
  value & opt_all regexp [ ("", `None) ] & info [ "l" ] ~doc ~docv:"REGEXP"

let setup_sources = function
  | [ (_, `None) ] -> None
  | res ->
      let res = List.map snd res in
      let res =
        List.fold_left
          (fun acc -> function `Re re -> re :: acc | _ -> acc)
          [] res
      in
      Some (Re.alt res)

let setup_sources = Term.(const setup_sources $ sources)

let setup_logs utf_8 style_renderer sources level =
  Option.iter (Fmt.set_style_renderer Fmt.stdout) style_renderer;
  Fmt.set_utf_8 Fmt.stdout utf_8;
  Logs.set_level level;
  Logs.set_reporter (reporter sources Fmt.stdout);
  Option.is_none level

let setup_logs =
  Term.(const setup_logs $ utf_8 $ renderer $ setup_sources $ verbosity)

let setup_nameservers = Mnet_cli.setup_nameservers ()

let destination =
  let doc =
    "The SMTP destination for outgoing mailing list emails (typically a signer \
     such as nec)."
  in
  let parser = Ipaddr.of_string and pp = Ipaddr.pp in
  let ipaddr = Arg.conv (parser, pp) in
  let open Arg in
  required & opt (some ipaddr) None & info [ "destination" ] ~doc ~docv:"IPADDR"

let submission_destination =
  let doc =
    "The SMTP destination for administrative emails generated by the mailing \
     list manager (subscription confirmations, etc.), typically a DKIM-only \
     signer."
  in
  let parser = Ipaddr.of_string and pp = Ipaddr.pp in
  let ipaddr = Arg.conv (parser, pp) in
  let open Arg in
  required
  & opt (some ipaddr) None
  & info [ "submission-destination" ] ~doc ~docv:"IPADDR"

let forward_granted_for =
  let doc =
    "CIDR prefix of peers whose emails should be forwarded directly to real \
     destinations (typically the local network where nec resides)."
  in
  let parser = Ipaddr.Prefix.of_string and pp = Ipaddr.Prefix.pp in
  let cidr = Arg.conv (parser, pp) in
  let open Arg in
  value & opt_all cidr [] & info [ "forward-granted-for" ] ~doc ~docv:"CIDR"

let docs_cert = "TLS CERTIFICATE"

let cert_dns =
  let doc = "Address of the DNS server for certificate retrieval." in
  let parser str = Ipaddr.with_port_of_string ~default:53 str in
  let pp ppf (ip, port) = Fmt.pf ppf "%a:%d" Ipaddr.pp ip port in
  let addr = Arg.conv (parser, pp) in
  let open Arg in
  required
  & opt (some addr) None
  & info [ "cert-dns" ] ~doc ~docs:docs_cert ~docv:"IPADDR:PORT"

let cert_dns_key =
  let doc = "DNS TSIG key for certificate retrieval and updates." in
  let parser = Dns.Dnskey.name_key_of_string in
  let pp = Fmt.using Dns.Dnskey.name_key_to_string Fmt.string in
  let key = Arg.conv (parser, pp) in
  let open Arg in
  required
  & opt (some key) None
  & info [ "cert-dns-key" ] ~doc ~docs:docs_cert ~docv:"NAME:ALGORITHM:DATA"

let cert_seed =
  let doc = "Seed for generating the CSR private key (base64-encoded)." in
  let parser str = Base64.decode str in
  let pp ppf str = Fmt.string ppf (Base64.encode_exn ~pad:true str) in
  let seed = Arg.conv (parser, pp) in
  let open Arg in
  required
  & opt (some seed) None
  & info [ "cert-seed" ] ~doc ~docs:docs_cert ~docv:"SEED"

let setup_cert (sinfo, _) cert_dns dns_key seed =
  let* hostname =
    match sinfo.Ptt.domain with
    | Domain vs ->
        let* raw = Domain_name.of_strings vs in
        Domain_name.host raw
    | IPv4 ipv4 -> Ok (Ipaddr.V4.to_domain_name ipv4)
    | IPv6 ipv6 -> Ok (Ipaddr.V6.to_domain_name ipv6)
    | Extension _ ->
        error_msgf "Impossible to launch a SMTP server with such domain: %a"
          Colombe.Domain.pp sinfo.Ptt.domain
  in
  Ok (hostname, cert_dns, dns_key, seed)

let setup_cert =
  let open Term in
  let term =
    const setup_cert $ Ptt_cli.term_info $ cert_dns $ cert_dns_key $ cert_seed
  in
  term_result term

let admin =
  let parser str =
    match String.split_on_char ':' str with
    | [ addr ] -> begin
        let fn m = (None, Colombe_emile.to_forward_path m) in
        Result.map fn (Emile.of_string addr)
        |> Result.map_error @@ function
           | `Msg _ as err -> err
           | `Invalid _ -> msgf "Invalid email: %S" addr
      end
    | local :: addr ->
        let addr = String.concat ":" addr in
        begin match (Emile.of_string addr, Mlm.local_of_string local) with
        | Ok mailbox, Ok local ->
            let local = Colombe_emile.of_local local in
            let forward_path = Colombe_emile.to_forward_path mailbox in
            Ok (Some local, forward_path)
        | Ok mailbox, Error _ ->
            let forward_path = Colombe_emile.to_forward_path mailbox in
            Ok (None, forward_path)
        | _ -> error_msgf "Impossible to parse %S as a email address" str
        end
    | [] -> assert false
  in
  (* NOTE(dinosaure): the [Option.get] should be safe because we don't try to
     encode [Postmaster] and/or [Domain]. *)
  let pp ppf = function
    | None, mailbox ->
        let mailbox = Colombe_emile.of_forward_path mailbox in
        let mailbox = Option.get mailbox in
        Fmt.string ppf (Emile.to_string mailbox)
    | Some local, mailbox ->
        let mailbox = Colombe_emile.of_forward_path mailbox in
        let mailbox = Option.get mailbox in
        Fmt.pf ppf "%s:%s" (Mlm.local_to_string local) (Emile.to_string mailbox)
  in
  let admin = Arg.conv (parser, pp) in
  let doc = "Email address to send administrative emails." in
  let open Arg in
  value & opt (some admin) None & info [ "admin" ] ~doc ~docv:"[LOCAL:]EMAIL"

let term =
  let open Term in
  const run
  $ setup_logs
  $ Mnet_cli.setup
  $ Ptt_cli.term_info
  $ setup_nameservers
  $ forward_granted_for
  $ destination
  $ submission_destination
  $ setup_cert
  $ admin

let cmd =
  let info = Cmd.info "lipap" ~doc:"Mailing list manager unikernel" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
