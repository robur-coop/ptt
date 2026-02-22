module RNG = Mirage_crypto_rng.Fortuna

let ( let@ ) finally fn = Fun.protect ~finally fn
let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

let setup_resolver udp he = function
  | `Nameservers ns ->
      let dns = Mnet_dns.create ~nameservers:ns (udp, he) in
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
  | `Static ipaddrs ->
      let gethostbyname ipaddrs _ = Result.ok ipaddrs
      and getmxbyname _ mail_exchange =
        Ok (Dns.Rr_map.Mx_set.singleton { preference= 0; mail_exchange })
      in
      Ptt.Resolver { gethostbyname; getmxbyname; dns= ipaddrs }
  | `None ->
      let gethostbyname () = error_msgf "%a not found" Domain_name.pp
      and getmxbyname () = error_msgf "%a (MX) not found" Domain_name.pp in
      Ptt.Resolver { gethostbyname; getmxbyname; dns= () }

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

let save_into bstr =
  let open Flux in
  let init = Fun.const (0, bstr)
  and push (dst_off, bstr) str =
    let len = String.length str in
    Bstr.blit_from_string str ~src_off:0 bstr ~dst_off ~len;
    (dst_off + len, bstr)
  and full (dst_off, bstr) = Bstr.length bstr = dst_off
  and stop (len, bstr) = Bstr.sub bstr ~off:0 ~len in
  Sink { init; push; full; stop }

let pp_dkim ppf = function
  | Dmarc.DKIM.Pass { dkim; _ } ->
      let domain_name = Dkim.domain dkim in
      Fmt.pf ppf "%a" Fmt.(styled (`Fg `Green) Domain_name.pp) domain_name
  | Dmarc.DKIM.Fail { dkim; _ } | Dmarc.DKIM.Permerror { dkim; _ } ->
      let domain_name = Dkim.domain dkim in
      Fmt.pf ppf "%a" Fmt.(styled (`Fg `Red) Domain_name.pp) domain_name
  | Dmarc.DKIM.Temperror { dkim; _ } ->
      let domain_name = Dkim.domain dkim in
      Fmt.pf ppf "%a" Fmt.(styled (`Fg `Yellow) Domain_name.pp) domain_name
  | Dmarc.DKIM.Neutral _ -> ()

let pp_result ppf = function
  | `Fail -> Fmt.pf ppf "%a" Fmt.(styled (`Fg `Red) string) "fail"
  | `Pass -> Fmt.pf ppf "%a" Fmt.(styled (`Fg `Green) string) "green"

let pp_dmarc ppf = function
  | Error err -> Analyze.pp_error ppf err
  | Ok (info, dkims, result) ->
      Fmt.pf ppf
        "{ @[<hov>spf=@ @[<hov>%a@];@ dmarc=@ @[<hov>%a@];@ domain=@ %a;@ \
         dkims=@ @[<hov>%a@];@ result=@ %a;@] }"
        Uspf.Result.pp info.Dmarc.Verify.spf Dmarc.pp info.Dmarc.Verify.dmarc
        Domain_name.pp info.Dmarc.Verify.domain
        Fmt.(Dump.list pp_dkim)
        dkims pp_result result

let handler pool info dns resolver flow =
  Cattery.use pool @@ fun v ->
  let _, (peer, port) = Mnet.TCP.peers flow in
  let ic = Miou.Computation.create () in
  let oc = Miou.Computation.create () in
  Logs.debug (fun m -> m "New client: %a:%d" Ipaddr.pp peer port);
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
      Ptt.Relay.handler ~encoder ~decoder ~queue ~info resolver flow (ic, oc) q
    with
    | Ok () -> Miou.Ownership.disown resource
    | Error err ->
        Miou.Ownership.release resource;
        Logs.err (fun m ->
            m "%a:%d finished with an error: %a" Ipaddr.pp peer port
              Ptt.Relay.pp_error err)
  in
  let prm1 =
    Miou.async @@ fun () ->
    match Miou.Computation.await_exn ic with
    | m ->
        assert (Miou.Computation.try_return oc `Ok);
        let from = Flux.Source.bqueue q in
        let stream = Flux.Stream.from from in
        let ctx = Uspf.empty in
        let ctx = Uspf.with_ip peer ctx in
        let ctx =
          let some v = Uspf.with_sender (`MAILFROM v) ctx in
          Option.fold ~none:ctx ~some (fst m.Ptt.from)
        in
        let dmarc = Analyze.dmarc ~ctx dns in
        let into =
          let open Flux.Sink.Syntax in
          let+ bstr = save_into v.contents
          and+ dmarc = dmarc
          and+ hdrs = Analyze.headers in
          (bstr, hdrs, dmarc)
        in
        let bstr, _hdrs, dmarc = Flux.Stream.into into stream in
        let hash = Digestif.SHA256.digest_bigstring bstr in
        Logs.debug (fun m -> m "New email: %a" Digestif.SHA256.pp hash);
        Logs.debug (fun m -> m "DMARC result: %a" pp_dmarc dmarc)
    | exception Ptt.Recipients_unreachable ->
        Logs.err (fun m -> m "Given recipients are unreachable")
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

let run _ (cidrv4, gateway, ipv6) info resolver nameservers =
  Mkernel.(run [ rng; Mnet.stack ~name:"service" ?gateway ~ipv6 cidrv4 ])
  @@ fun rng (stack, tcp, udp) () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill stack in
  let hed, he = Mnet_happy_eyeballs.create tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let dns = Mnet_dns.create ~nameservers (udp, he) in
  let t = Mnet_dns.transport dns in
  let@ () = fun () -> Mnet_dns.Transport.kill t in
  let seed = "TIDeanAhmWotZvWdrJntsKTwyAg16ysFhIYhSErjc8Q=" in
  let result = CA.make (Colombe.Domain.to_string info.Ptt.domain) ~seed in
  let cert, pk, _authenticator = Result.get_ok result in
  Logs.debug (fun m -> m "CA and certificate generated");
  let tls = Tls.Config.server ~certificates:(`Single ([ cert ], pk)) () in
  let tls = Result.get_ok tls in
  let info = { info with Ptt.tls= Some tls } in
  let resolver = setup_resolver udp he resolver in
  let pool =
    Cattery.create 16 @@ fun () ->
    let encoder = Bytes.create 4096 in
    let decoder = Bytes.create 4096 in
    let queue = Ke.Rke.create Bigarray.char ~capacity:0x1000 in
    let contents = Bstr.create info.size in
    { encoder; decoder; queue; contents }
  in
  let rec go orphans listen =
    clean_up orphans;
    let flow = Mnet.TCP.accept tcp listen in
    let _ =
      Miou.async ~orphans @@ fun () -> handler pool info dns resolver flow
    in
    go orphans listen
  in
  go (Miou.orphans ()) (Mnet.TCP.listen tcp 25)

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

let forward_to =
  let doc =
    "Redirects all emails to a specific IP address (and ignores DNS \
     resolution)."
  in
  let parser = Ipaddr.of_string in
  let pp = Ipaddr.pp in
  let open Arg in
  value
  & opt_all (conv (parser, pp)) []
  & info [ "forward-to" ] ~doc ~docv:"IPADDR"

let setup_resolution nameservers forward_to =
  match (nameservers, forward_to) with
  | (_, []), [] -> `None
  | (proto, ns), [] -> `Nameservers (proto, ns)
  | _, forward_to -> `Static forward_to

let setup_nameservers = Mnet_cli.setup_nameservers ()

let setup_resolution =
  let open Term in
  const setup_resolution $ setup_nameservers $ forward_to

let term =
  let open Term in
  const run
  $ setup_logs
  $ Mnet_cli.setup
  $ Ptt_cli.term_info
  $ setup_resolution
  $ setup_nameservers

let cmd =
  let info = Cmd.info "elit" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
