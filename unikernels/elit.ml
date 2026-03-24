module Blk = struct
  type t = Mkernel.Block.t

  let pagesize = Mkernel.Block.pagesize
  let read = Mkernel.Block.atomic_read
  let write = Mkernel.Block.atomic_write
end

module Fat = Mfat.Make (Blk)
module RNG = Mirage_crypto_rng.Fortuna
open Utils
module SM = Map.Make (String)

let ( let@ ) finally fn = Fun.protect ~finally fn
let ( let* ) = Result.bind
let ( / ) = Filename.concat
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let gen_id =
  let counter = Atomic.make 0 in
  fun () ->
    let n = Atomic.fetch_and_add counter 1 in
    Printf.sprintf "%d-%d" (Stdlib.Domain.self () :> int) n

let find_list lists rcpt_local rcpt_domain =
  SM.fold
    (fun name lst acc ->
      match acc with
      | Some _ -> acc
      | None ->
          let lst_domain = Colombe.Domain.to_string lst.Mlm.domain in
          if not (String.equal lst_domain rcpt_domain) then None
          else
            let nlen = String.length name in
            let rlen = String.length rcpt_local in
            if
              rlen >= nlen
              && String.sub rcpt_local 0 nlen = name
              && (rlen = nlen || rcpt_local.[nlen] = '-')
            then Some lst
            else None)
    lists None

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

type cfg = {
    forward: Ipaddr.t -> bool
  ; pool: value Cattery.t
  ; resolver: Ptt.resolver
  ; client: Facteur.t
  ; lists: Mlm.t SM.t ref
  ; save_list: Mlm.t -> unit
}

let rec send_mlm_outgoing ~cfg ~info resolver lst outgoing =
  List.fold_left
    (fun lst (out : Mlm.outgoing) ->
      let from = out.Mlm.sender in
      let recipients = out.Mlm.recipients in
      match recipients with
      | _ :: _ ->
          let seq =
            Seq.forever @@ fun () ->
            Flux.Stream.from (Flux.Source.list [ out.Mlm.data ])
          in
          let errors =
            Facteur.sendmail cfg.client ~info resolver ~from recipients seq
          in
          if errors <> [] then
            begin match from with
            | Some verp_path -> (
                let verp_fp = Colombe.Forward_path.Forward_path verp_path in
                match
                  Mlm.incoming ~gen_id lst ~from:None ~rcpt:verp_fp ~mail:""
                with
                | Ok (lst', bounce_out) ->
                    ignore
                      (send_mlm_outgoing ~cfg ~info resolver lst' bounce_out);
                    lst'
                | Error () -> lst)
            | None -> lst
            end
          else lst
      | [] ->
          Logs.warn (fun m -> m "MLM: no recipients for outgoing email");
          lst)
    lst outgoing

let resolver_according_to_peer ~cfg ~destination flow =
  let _, (peer, _) = Mnet.TCP.peers flow in
  match cfg.forward peer with
  | true -> cfg.resolver
  | false ->
      let gethostbyname ipaddrs _ = Result.ok ipaddrs
      and getmxbyname _ mail_exchange =
        Ok (Dns.Rr_map.Mx_set.singleton { preference= 0; mail_exchange })
      in
      Ptt.Resolver { gethostbyname; getmxbyname; dns= [ destination ] }

let to_forward ~cfg flow =
  let _, (peer, _) = Mnet.TCP.peers flow in
  cfg.forward peer

let handler_mx ?(with_arc = false) ~cfg ~info:(sinfo, cinfo) dns destination
    flow =
  Cattery.use cfg.pool @@ fun v ->
  let resolver = resolver_according_to_peer ~cfg ~destination flow in
  let forward = to_forward ~cfg flow in
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
    | m when forward ->
        assert (Miou.Computation.try_return oc `Ok);
        let from = Flux.Source.bqueue q in
        let stream = Flux.Stream.from from in
        let bstr = Flux.Stream.into (save_into v.contents) stream in
        let seq = Seq.forever @@ fun () -> Flux.Stream.from (from_bstr bstr) in
        let from = fst m.Ptt.from in
        let recipients = List.map fst m.Ptt.recipients in
        ignore
          (Facteur.sendmail cfg.client ~info:cinfo resolver ~from recipients seq)
    | m ->
        assert (Miou.Computation.try_return oc `Ok);
        let from_source = Flux.Source.bqueue q in
        let stream = Flux.Stream.from from_source in
        let from = fst m.Ptt.from in
        let list_rcpts, other_rcpts =
          List.fold_right
            (fun (fp, params) (lists, others) ->
              match fp with
              | Colombe.Forward_path.Forward_path path -> (
                  let local =
                    Colombe.Path.Encoder.local_to_string path.Colombe.Path.local
                  in
                  let domain =
                    Colombe.Domain.to_string path.Colombe.Path.domain
                  in
                  match find_list !(cfg.lists) local domain with
                  | Some lst -> ((lst, fp) :: lists, others)
                  | None -> (lists, (fp, params) :: others))
              | _ -> (lists, (fp, params) :: others))
            m.Ptt.recipients ([], [])
        in
        let ctx = Uspf.empty in
        let ctx = Uspf.with_ip peer ctx in
        let ctx =
          let some v = Uspf.with_sender (`MAILFROM v) ctx in
          Option.fold ~none:ctx ~some (fst m.Ptt.from)
        in
        let into =
          let open Flux.Sink.Syntax in
          let+ bstr = save_into v.contents
          and+ dmarc = dmarc ~ctx dns
          and+ hdrs = headers in
          (bstr, hdrs, dmarc)
        in
        let bstr, hdrs, dmarc_result = Flux.Stream.into into stream in
        if list_rcpts <> [] then begin
          let max_size = sinfo.Ptt.size in
          let mail_len = Bstr.length bstr in
          if mail_len > max_size then
            Logs.warn (fun m ->
                m "MLM: email too large (%d bytes, max %d)" mail_len max_size)
          else begin
            let mail = Bstr.to_string bstr in
            List.iter
              (fun (lst, rcpt_fp) ->
                match Mlm.incoming ~gen_id lst ~from ~rcpt:rcpt_fp ~mail with
                | Ok (lst', outgoing) ->
                    let lst' =
                      send_mlm_outgoing ~cfg ~info:cinfo resolver lst' outgoing
                    in
                    cfg.lists := SM.add lst'.Mlm.name lst' !(cfg.lists);
                    cfg.save_list lst'
                | Error () ->
                    Logs.warn (fun m ->
                        m "MLM: no matching handler for %a"
                          Colombe.Forward_path.pp rcpt_fp))
              list_rcpts
          end
        end;
        if other_rcpts <> [] then
          begin match (hdrs, dmarc_result) with
          | Error err, _ ->
              Logs.err (fun m ->
                  m "Invalid incoming email: %a" Utils.pp_error err)
          | _, Error err ->
              Logs.err (fun m -> m "DMARC error: %a" Utils.pp_error err)
          | Ok hdrs, Ok dmarc ->
              let aresults =
                let receiver = receiver ~info:sinfo in
                if with_arc then
                  let uid = last_arc_set hdrs in
                  Arc.Encoder.stamp_results ~receiver ~uid:(succ uid)
                else aresults ~receiver
              in
              let aresults =
                Prettym.to_string ~new_line:"\r\n" aresults dmarc
              in
              let s0 = Flux.Stream.from (Flux.Source.list [ aresults ]) in
              let s1 = Flux.Stream.from (from_bstr bstr) in
              let seq = Seq.forever @@ fun () -> Flux.Stream.concat s0 s1 in
              let from = fst m.Ptt.from in
              let recipients = List.map fst other_rcpts in
              ignore
                (Facteur.sendmail cfg.client ~info:cinfo resolver ~from
                   recipients seq)
          end
    | exception Ptt.Recipients_unreachable ->
        Logs.err (fun m -> m "Given recipients are unreachable")
    | exception Handler_failed -> Logs.err (fun m -> m "Relay handler failed")
  in
  let _ = Miou.await prm0 in
  let () = Miou.await_exn prm1 in
  Mnet.TCP.close flow

type user = {
    username: [ `Dot_string of string list | `String of string ]
  ; password: Digestif.SHA256.t
  ; is_admin: bool
}

let user =
  let open Digestif in
  let open Jsont in
  let open Object in
  let local =
    let dec str =
      Angstrom.parse_string ~consume:All Colombe.Path.Decoder.local_part str
      |> Result.error_to_failure
    in
    let enc = Colombe.Path.Encoder.local_to_string in
    Jsont.map ~enc ~dec string
  in
  let sha256 =
    let enc = SHA256.to_hex and dec = SHA256.of_hex in
    Jsont.map ~enc ~dec string
  in
  Object.map (fun username password is_admin ->
      let is_admin = Option.value ~default:false is_admin in
      { username; password; is_admin })
  |> mem "username" local
  |> mem "password" sha256
  |> opt_mem "is_admin" bool
  |> Object.finish

let auth fs username password =
  let* users = Fat.ls fs "users/" in
  let fn { Mfat.name; _ } = Eqaf.equal name username in
  match List.find_opt fn users with
  | Some { Mfat.name; is_dir= false; _ } ->
      let str = Fat.read fs ("users" / name) in
      let str = Result.get_ok str in
      let* t =
        Jsont_bytesrw.decode user (Bytesrw.Bytes.Reader.of_string str)
        |> Result.map_error (fun _ -> msgf "Invalid JSON value for %s" username)
      in
      let password = Digestif.SHA256.digest_string password in
      Ok (Digestif.SHA256.equal password t.password)
  | _ -> Ok false

let handler_submission ~cfg ~info:(sinfo, _cinfo) fs destination flow =
  Cattery.use cfg.pool @@ fun v ->
  let fd = Mnet_tls.file_descr flow in
  let resolver = resolver_according_to_peer ~cfg ~destination fd in
  let _, (peer, port) = Mnet.TCP.peers fd in
  let ic = Miou.Computation.create () in
  let oc = Miou.Computation.create () in
  let q = Flux.Bqueue.(create with_close) 0x7ff in
  let authentication =
    let verify (`PLAIN stamp) value =
      let* str = Base64.decode ~pad:false value in
      match (stamp, String.split_on_char '\000' str) with
      | None, "" :: username :: password ->
          let password = String.concat "\000" password in
          let* authentified = auth fs username password in
          Ok (username, authentified)
      | Some stamp', stamp :: username :: password when Eqaf.equal stamp stamp'
        ->
          let password = String.concat "\000" password in
          let* authentified = auth fs username password in
          Ok (username, authentified)
      | _, _ :: username :: _ -> Ok (username, false)
      | _ -> error_msgf "Invalid authentication"
    in
    ([ Ptt.Mechanism.PLAIN ], verify)
  in
  let prm0 =
    Miou.async @@ fun () ->
    let finally ic = assert (Miou.Computation.try_cancel ic handler_failed) in
    let resource = Miou.Ownership.create ~finally ic in
    Miou.Ownership.own resource;
    let encoder = Fun.const v.encoder and decoder = Fun.const v.decoder in
    match
      Ptt.Submission.handler ~encoder ~decoder ~info:sinfo resolver
        authentication flow (ic, oc) q
    with
    | Ok () -> Miou.Ownership.disown resource
    | Error (`Msg msg) ->
        Miou.Ownership.release resource;
        Logs.err (fun m ->
            m "%a:%d finished with an error: %s" Ipaddr.pp peer port msg)
    | Error (#Ptt.Submission.error as err) ->
        Miou.Ownership.release resource;
        Logs.err (fun m ->
            m "%a:%d finished with an error: %a" Ipaddr.pp peer port
              Ptt.Submission.pp_error err)
  in
  let prm1 =
    Miou.async @@ fun () ->
    match Miou.Computation.await_exn ic with
    | _m -> assert false
    | exception Ptt.Recipients_unreachable ->
        Logs.err (fun m -> m "Given recipients are unreachable")
    | exception Handler_failed ->
        Logs.err (fun m -> m "Submission handler failed")
  in
  let _ = Miou.await prm0 in
  let () = Miou.await_exn prm1 in
  Mnet_tls.close flow

let rec clean_up orphans =
  match Miou.care orphans with
  | Some None | None -> ()
  | Some (Some prm) ->
      let _ = Miou.await prm in
      clean_up orphans

let mx ?(with_arc = false) ~cfg ~info tcp dns destination =
  let handler = handler_mx ~with_arc ~cfg ~info dns destination in
  let rec go orphans listen =
    clean_up orphans;
    let flow = Mnet.TCP.accept tcp listen in
    let _ = Miou.async ~orphans @@ fun () -> handler flow in
    go orphans listen
  in
  go (Miou.orphans ()) (Mnet.TCP.listen tcp 25)

let submission ~tls ~cfg ~info tcp fs destination =
  let handler = handler_submission ~cfg ~info fs destination in
  let rec go orphans listen =
    clean_up orphans;
    let flow = Mnet.TCP.accept tcp listen in
    let _ =
      Miou.async @@ fun () ->
      match Mnet_tls.server_of_fd tls flow with
      | flow -> handler flow
      | exception exn ->
          let (s, sp), (c, cp) = Mnet.TCP.peers flow in
          Logs.err (fun m ->
              m "Got an unexpected exception from %a:%d (on %a:%d): %s"
                Ipaddr.pp c cp Ipaddr.pp s sp (Printexc.to_string exn));
          Mnet.TCP.close flow
    in
    go orphans listen
  in
  go (Miou.orphans ()) (Mnet.TCP.listen tcp 587)

let fat ~name =
  let fn blk () =
    let v = Fat.create blk in
    let v = Result.map_error (fun (`Msg msg) -> msg) v in
    Result.error_to_failure v
  in
  Mkernel.map fn [ Mkernel.block name ]

let run _ (cidrv4, gateway, ipv6) info resolver nameservers forward_granted_for
    dst0 dst1 with_arc =
  let devices =
    let open Mkernel in
    [ rng; Mnet.stack ~name:"service" ?gateway ~ipv6 cidrv4; fat ~name:"elit" ]
  in
  Mkernel.run devices @@ fun rng (stack, tcp, udp) fs () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill stack in
  let hed, he = Mnet_happy_eyeballs.create tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let dns = Mnet_dns.create ~nameservers (udp, he) in
  let t = Mnet_dns.transport dns in
  let@ () = fun () -> Mnet_dns.Transport.kill t in
  let seed = "TIDeanAhmWotZvWdrJntsKTwyAg16ysFhIYhSErjc8Q=" in
  let result = CA.make (Colombe.Domain.to_string (fst info).Ptt.domain) ~seed in
  let cert, pk, _authenticator = Result.get_ok result in
  Logs.debug (fun m -> m "CA and certificate generated");
  let tls = Tls.Config.server ~certificates:(`Single ([ cert ], pk)) () in
  let tls = Result.get_ok tls in
  let info = ({ (fst info) with Ptt.tls= Some tls }, snd info) in
  let resolver = setup_resolver udp he resolver in
  let pool =
    Cattery.create 16 @@ fun () ->
    let encoder = Bytes.create 4096 in
    let decoder = Bytes.create 4096 in
    let queue = Ke.Rke.create Bigarray.char ~capacity:0x1000 in
    let contents = Bstr.create (fst info).size in
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
  let forward ipaddr =
    let fn = Ipaddr.Prefix.mem ipaddr in
    List.exists fn forward_granted_for
  in
  let lists =
    let load () =
      match Fat.ls fs "lists/" with
      | Ok entries ->
          List.fold_left
            (fun acc entry ->
              if
                (not entry.Mfat.is_dir)
                && Filename.check_suffix entry.Mfat.name ".conf"
              then (
                match Fat.read fs ("lists" / entry.Mfat.name) with
                | Ok data ->
                    let lst =
                      Mlm.of_config ~domain:(fst info).Ptt.domain data
                    in
                    Logs.info (fun m ->
                        m "Loaded mailing list: %s" lst.Mlm.name);
                    SM.add lst.Mlm.name lst acc
                | Error (`Msg msg) ->
                    Logs.warn (fun m ->
                        m "Cannot read list %s: %s" entry.Mfat.name msg);
                    acc)
              else acc)
            SM.empty entries
      | Error _ ->
          (match Fat.mkdir fs "lists" with
          | Ok () -> Logs.info (fun m -> m "Created lists/ directory")
          | Error (`Msg msg) ->
              Logs.warn (fun m -> m "Cannot create lists/ directory: %s" msg));
          SM.empty
    in
    ref (load ())
  in
  let save_list lst =
    let data = Mlm.to_config lst in
    let path = "lists" / (lst.Mlm.name ^ ".conf") in
    match Fat.write fs path data with
    | Ok () ->
        Logs.debug (fun m -> m "Saved mailing list state: %s" lst.Mlm.name)
    | Error (`Msg msg) ->
        Logs.err (fun m -> m "Failed to save list %s: %s" lst.Mlm.name msg)
  in
  let cfg = { forward; pool; resolver; client; lists; save_list } in
  let prm0 = Miou.async @@ fun () -> mx ~with_arc ~cfg ~info tcp dns dst0 in
  let prm1 = Miou.async @@ fun () -> submission ~tls ~cfg ~info tcp fs dst1 in
  Miou.await_all [ prm0; prm1 ]
  |> List.iter (function Ok () -> () | Error exn -> raise exn)

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

let mx_destination =
  let doc =
    "The SMTP destination for incoming emails on $(b,*:25) whose source IP \
     address is not one of the addresses whose emails should be forwarded."
  in
  let parser = Ipaddr.of_string and pp = Ipaddr.pp in
  let ipaddr = Arg.conv (parser, pp) in
  let open Arg in
  required
  & opt (some ipaddr) None
  & info [ "mx-destination" ] ~doc ~docv:"IPADDR"

let submission_destination =
  let doc =
    "The SMTP destination for incoming emails on $(b,*:587) whose source IP \
     address is not one of the addresses whose emails should be forwarded."
  in
  let parser = Ipaddr.of_string and pp = Ipaddr.pp in
  let ipaddr = Arg.conv (parser, pp) in
  let open Arg in
  required
  & opt (some ipaddr) None
  & info [ "submission-destination" ] ~doc ~docv:"IPADDR"

let forward_granted_for =
  let doc = "Client emails whose received email should only be forwarded." in
  let parser = Ipaddr.Prefix.of_string and pp = Ipaddr.Prefix.pp in
  let cidr = Arg.conv (parser, pp) in
  let open Arg in
  value & opt_all cidr [] & info [ "forward-granted-for" ] ~doc ~docv:"CIDR"

let with_arc =
  let doc =
    "Adds an ARC-Authentication-Results field to incoming emails (so that a \
     signer can sign the email of a new ARC set). Otherwise, adds an \
     Authentication-Results field."
  in
  let open Arg in
  value & flag & info [ "with-arc" ] ~doc

let term =
  let open Term in
  const run
  $ setup_logs
  $ Mnet_cli.setup
  $ Ptt_cli.term_info
  $ setup_resolution
  $ setup_nameservers
  $ forward_granted_for
  $ mx_destination
  $ submission_destination
  $ with_arc

let cmd =
  let info = Cmd.info "elit" in
  Cmd.v info term

let () = Cmd.(exit @@ eval cmd)
