type selector =
  ( int -> [ `raw ] Domain_name.t
  , Format.formatter
  , unit
  , [ `raw ] Domain_name.t )
  format4

type private_key =
  | PBKDF2 of { password: string; alg: [ `RSA of int | `ED25519 ] }
  | Private_key of Dkim.key

type mode =
  | DKIM of {
        private_key: private_key
      ; hash: Dkim.hash
      ; canonicalization: Dkim.canonicalization * Dkim.canonicalization
      ; fields: Mrmime.Field_name.t list
      ; selector: [ `raw ] Domain_name.t option
      ; domain: [ `raw ] Domain_name.t
      ; expiration: Ptime.t option
      ; fmt: selector
    }

module RNG = Mirage_crypto_rng.Fortuna

let ( let@ ) finally fn = Fun.protect ~finally fn
let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
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

let _from_bstr ?(len = 0x7ff) bstr =
  let open Flux in
  let buf = Bytes.create len in
  let init = Fun.const 0
  and pull src_off =
    let len = Int.min (Bstr.length bstr - src_off) (Bytes.length buf) in
    if len = 0 then None
    else begin
      Bstr.blit_to_bytes bstr ~src_off buf ~dst_off:0 ~len;
      let str = Bytes.sub_string buf 0 len in
      Some (str, src_off + len)
    end
  and stop = Fun.const () in
  Source { init; pull; stop }

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
    | _m ->
        assert (Miou.Computation.try_return oc `Ok);
        let from = Flux.Source.bqueue q in
        let stream = Flux.Stream.from from in
        let into =
          let open Flux.Sink.Syntax in
          let+ bstr = save_into v.contents
          and+ chain = Analyze.chain dns
          and+ hdrs = Analyze.headers in
          (bstr, hdrs, chain)
        in
        let bstr, _hdrs, _chain = Flux.Stream.into into stream in
        let _hash = Digestif.SHA256.digest_bigstring bstr in
        assert false
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

let verify_primary dns dkim dk =
  let* domain_name = Dkim.Verify.domain_key dkim in
  let* _, sstr = Mnet_dns.get_resource_record dns Dns.Rr_map.Txt domain_name in
  let sstr = Dns.Rr_map.Txt_set.elements sstr in
  let str = String.concat "" sstr in
  let* dk' = Dkim.domain_key_of_string str in
  Dkim.equal_domain_key dk dk'

let handle_domain_key dns = function
  | DKIM { private_key= Private_key pk; _ } ->
  | DKIM { private_key= PBKDF2 _; _ } ->
  | _ -> assert false

let run _ (cidrv4, gateway, ipv6) info nameservers destination mode primary =
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
  let pool =
    Cattery.create 16 @@ fun () ->
    let encoder = Bytes.create 4096 in
    let decoder = Bytes.create 4096 in
    let queue = Ke.Rke.create Bigarray.char ~capacity:0x1000 in
    let contents = Bstr.create info.size in
    { encoder; decoder; queue; contents }
  in
  let resolver =
    let gethostbyname ipaddrs _ = Result.ok ipaddrs
    and getmxbyname _ mail_exchange =
      Ok (Dns.Rr_map.Mx_set.singleton { preference= 0; mail_exchange })
    in
    Ptt.Resolver { gethostbyname; getmxbyname; dns= [ destination ] }
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

let fields =
  let doc = "List of fields to sign." in
  let field = Arg.conv Mrmime.Field_name.(of_string, pp) in
  let from = Mrmime.Field_name.from in
  let open Arg in
  value & opt_all field [ from ] & info [ "f"; "field" ] ~doc ~docv:"FIELD"

let selector =
  let doc = "The DKIM/ARC selector." in
  let domain_name = Arg.conv Domain_name.(of_string, pp) in
  let open Arg in
  value
  & opt (some domain_name) None
  & info [ "s"; "selector" ] ~doc ~docv:"SELECTOR"

let expiration =
  let doc = "Date on which the key must expire." in
  let parser str =
    match Ptime.of_rfc3339 str with
    | Ok (ptime, _tz, _) -> Ok ptime
    | Error _ -> error_msgf "Invalid RFC3339 date: %S" str
  in
  let pp = Ptime.pp_rfc3339 () in
  let ptime = Arg.conv (parser, pp) in
  let open Arg in
  value & opt (some ptime) None & info [ "x"; "expiration" ] ~doc ~docv:"DATE"

let hash =
  let doc = "The hash algorithm used to sign emails." in
  let parser str =
    match String.lowercase_ascii str with
    | "sha1" -> Ok `SHA1
    | "sha256" -> Ok `SHA256
    | _ -> error_msgf "Invalid hash algorithm: %S" str
  in
  let pp ppf = function
    | `SHA1 -> Fmt.string ppf "sha1"
    | `SHA256 -> Fmt.string ppf "sha256"
  in
  let hash = Arg.conv (parser, pp) in
  let open Arg in
  value & opt hash `SHA256 & info [ "hash" ] ~doc ~docv:"HASH"

let canonicalization =
  let doc = "The canonicalization algorithm used to sign emails." in
  let parser str =
    let str = String.lowercase_ascii str in
    match String.split_on_char '/' str with
    | [ "relaxed" ] | [ "relaxed"; "relaxed" ] -> Ok (`Relaxed, `Relaxed)
    | [ "simple" ] | [ "simple"; "simple" ] -> Ok (`Simple, `Simple)
    | [ "relaxed"; "simple" ] -> Ok (`Relaxed, `Simple)
    | [ "simple"; "relaxed" ] -> Ok (`Simple, `Relaxed)
    | _ -> error_msgf "Invalid canonicalization algorithm: %S" str
  in
  let pp ppf = function
    | `Relaxed, `Relaxed -> Fmt.string ppf "relaxed"
    | `Simple, `Simple -> Fmt.string ppf "simple"
    | `Relaxed, `Simple -> Fmt.string ppf "relaxed/simple"
    | `Simple, `Relaxed -> Fmt.string ppf "simple/relaxed"
  in
  let canonicalization = Arg.conv (parser, pp) in
  let open Arg in
  value
  & opt canonicalization (`Relaxed, `Relaxed)
  & info [ "c" ] ~doc ~docv:"CANON[/CANON]"

let power_of_two x = x land (x - 1) = 0 && x <> 0

let algorithm =
  let doc = "Encryption algorithm used to sign emails." in
  let bits_of_string str =
    match int_of_string str with
    | bits -> Ok bits
    | exception _ -> error_msgf "Invalid bits value: %s" str
  in
  let parser str =
    let str = String.lowercase_ascii str in
    match String.split_on_char '/' str with
    | [ "rsa" ] -> Ok (`RSA 4096)
    | [ "ed25519" ] -> Ok `ED25519
    | [ "rsa"; bits ] ->
        let* bits = bits_of_string bits in
        if power_of_two bits && bits >= 2048 then Ok (`RSA bits)
        else error_msgf "Invalid bits to generate a RSA key"
    | _ -> error_msgf "Invalid encryption algorithm to use: %S" str
  in
  let pp ppf = function
    | `RSA bits -> Fmt.pf ppf "rsa/%d" bits
    | `ED25519 -> Fmt.string ppf "ed25519"
  in
  let alg = Arg.conv (parser, pp) in
  let open Arg in
  value & opt alg `ED25519 & info [ "a"; "algorithm" ] ~doc ~docv:"ALGORITHM"

let password =
  let doc =
    "The password ($(i,base64) encoded) used to generate (via $(i,PBKDF2)) a \
     private key."
  in
  let parser str = Base64.decode str in
  let pp ppf str = Fmt.string ppf (Base64.encode_exn ~pad:true str) in
  let password = Arg.conv (parser, pp) in
  let open Arg in
  value
  & opt (some password) None
  & info [ "p"; "password" ] ~doc ~docv:"PASSWORD"

type key =
  [ `RSA of Mirage_crypto_pk.Rsa.priv
  | `ED25519 of Mirage_crypto_ec.Ed25519.priv ]

let private_key =
  let doc = "The private key used to sign emails." in
  let parser str =
    let* key = Base64.decode ~pad:true str in
    match X509.Private_key.decode_der key with
    | Ok #key as value -> value
    | Ok _ -> error_msgf "We only support RSA/ED25519 keys"
    | Error _ as err -> err
  in
  let pp ppf (key : key) =
    Fmt.string ppf (X509.Private_key.encode_der (key :> X509.Private_key.t))
  in
  let key = Arg.conv (parser, pp) in
  let open Arg in
  value & opt (some key) None & info [ "private-key" ] ~doc ~docv:"DER"

let setup_private_key pk password alg =
  match (pk, password) with
  | Some pk, None -> Ok (Key pk)
  | None, Some password -> Ok (PBKDF2 { password; alg })
  | Some pk, Some _ ->
      Logs.warn (fun m ->
          m "Ignore the user's password, we prefer to use the given private key");
      Ok (Key pk)
  | None, None ->
      error_msgf
        "A private key (from a password or a DER-encoded private key) is \
         required"

let setup_private_key =
  let open Term in
  let term = const setup_private_key $ private_key $ password $ algorithm in
  term_result ~usage:true term

let sel fmt = Fmt.kstr (fun str -> Domain_name.of_string_exn str) fmt

let setup_dkim info private_key fields selector hash canonicalization expiration
    =
  let domain =
    match info.Ptt.domain with
    | Colombe.Domain.IPv4 ipv4 ->
        Domain_name.raw (Ipaddr.V4.to_domain_name ipv4)
    | IPv6 ipv6 -> Domain_name.raw (Ipaddr.V6.to_domain_name ipv6)
    | Extension (k, v) -> Fmt.failwith "Impossible to handle [%s:%s]" k v
    | Domain vs ->
        let str = String.concat "." vs in
        Domain_name.of_string_exn str
  in
  Ok
    (DKIM
       {
         private_key
       ; hash
       ; canonicalization
       ; fields
       ; selector
       ; domain
       ; expiration
       ; fmt= ("sel%d" : selector)
       })

let setup_dkim =
  let open Term in
  let term =
    const setup_dkim
    $ Ptt_cli.term_info
    $ setup_private_key
    $ fields
    $ selector
    $ hash
    $ canonicalization
    $ expiration
  in
  term_result ~usage:true term

let destination =
  let doc = "The SMTP destination for all signed emails." in
  let ipaddr = Arg.conv Ipaddr.(of_string, pp) in
  let open Arg in
  required & opt (some ipaddr) None & info [ "dst" ] ~doc ~docv:"IPADDR"

let dns_server =
  let doc = "Address of the primary DNS server." in
  let parser str = Ipaddr.with_port_of_string ~default:53 str in
  let pp ppf (ipaddr, port) = Fmt.pf ppf "%a:%d" Ipaddr.pp ipaddr port in
  let addr = Arg.conv (parser, pp) in
  let open Arg in
  value & opt (some addr) None & info [ "dns-server" ] ~doc ~docv:"IPADDR:PORT"

let dns_key =
  let doc = "DNS key to update the primary DNS server." in
  let parser = Dns.Dnskey.name_key_of_string in
  let pp = Fmt.using Dns.Dnskey.name_key_to_string Fmt.string in
  let key = Arg.conv (parser, pp) in
  let open Arg in
  value
  & opt (some key) None
  & info [ "dns-key" ] ~doc ~docv:"NAME:ALGORITHM:DATA"

let setup_dns_server dns_server dns_key =
  match (dns_server, dns_key) with
  | Some server, Some key -> Ok (Some (server, key))
  | None, None -> Ok None
  | Some (addr, port), _ ->
      error_msgf "DNS key missing to communicate with %a:%d" Ipaddr.pp addr port
  | None, Some _ -> error_msgf "DNS server missing"

let setup_dns_server =
  let open Term in
  let term = const setup_dns_server $ dns_server $ dns_key in
  term_result ~usage:true term

let term =
  let open Term in
  const run
  $ setup_logs
  $ Mnet_cli.setup
  $ Ptt_cli.term_info
  $ setup_nameservers
  $ destination
  $ setup_dkim
  $ setup_dns_server

let cmd =
  let info = Cmd.info "elit" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
