[@@@warning "-37"]

let ( let@ ) finally fn = Fun.protect ~finally fn
let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

open Utils

type private_key =
  | PBKDF2 of { password: string; alg: [ `RSA of int | `ED25519 ] }
  | Private_key of Dkim.key
  | No_private_key

(* NOTE(dinosaure): [No_private_key] is a value that is used when configuring
   [nec] to sign with a new [ARC-Set]. In this case, we also have a DKIM
   configuration that requires a private key. Currently, the same private key
   is used to sign the new [ARC-Set] and the email content (which greatly
   simplifies the code).

   We could use a GADT and invalidate the [No_private_key] case, but still
   create such a value with [Obj.magic] so that [private_key] is both
   exhaustive and returns a key in all cases, but I'm not sure that's very
   interesting. *)

let private_key ?(count = 1) domain_name = function
  | Private_key (`RSA _ as key) -> Ok (key, `RSA)
  | Private_key (`ED25519 _ as key) -> Ok (key, `ED25519)
  | PBKDF2 { password; alg } -> begin
      let salt = Domain_name.to_string domain_name ^ ":ptt" in
      let dk_len = 32l in
      Logs.debug (fun m -> m "Generate a new key with count=%d" count);
      let seed = Pbkdf.pbkdf2 ~prf:`SHA256 ~password ~salt ~count ~dk_len in
      let g = Mirage_crypto_rng.(create ~seed (module Fortuna)) in
      match alg with
      | `RSA bits ->
          let pk = Mirage_crypto_pk.Rsa.generate ~g ~bits () in
          Ok (`RSA pk, `RSA)
      | `ED25519 ->
          let pk, _ = Mirage_crypto_ec.Ed25519.generate ~g () in
          Ok (`ED25519 pk, `ED25519)
    end
  | No_private_key -> error_msgf "Private key missing"

module DKIM = struct
  type cfg = {
      pk: private_key
    ; hash: Dkim.hash
    ; canonicalization: Dkim.canonicalization * Dkim.canonicalization
    ; fields: Mrmime.Field_name.t list
    ; expiration: [ `At of Ptime.t | `For of Ptime.span ] option
    ; selector: [ `Fixed of [ `raw ] Domain_name.t | `Fmt of Dks.selector ]
  }

  type t = {
      mutable dkim: Dkim.unsigned Dkim.t
    ; mutable domain_key: Dkim.domain_key
    ; mutable key: Dkim.key
    ; mutable count: int
    ; pk: private_key
    ; hash: Dkim.hash
    ; domain_name: [ `raw ] Domain_name.t
  }

  let of_cfg ~selector ~alg:algorithm ?expiration cfg domain_name =
    let version = 1
    and fields = cfg.fields
    and hash = cfg.hash
    and canonicalization = cfg.canonicalization
    and query = `DNS `TXT in
    Dkim.v ~version ~fields ~selector ~algorithm ~hash ~canonicalization ~query
      ?expiration domain_name

  let v ?(count = 1) ~cfg ?x:expiration ~selector pk domain_name =
    let* key, alg = private_key ~count domain_name pk in
    let dkim = of_cfg ~selector ~alg ?expiration cfg domain_name in
    let hash = cfg.hash in
    let domain_key = Dkim.domain_key_of_dkim ~key dkim in
    Ok { dkim; domain_key; key; count; hash; pk; domain_name }
end

module ARC = struct
  type cfg = {
      pk: private_key
    ; hash: Dkim.hash
    ; expiration: [ `At of Ptime.t | `For of Ptime.span ] option
    ; selector: [ `Fixed of [ `raw ] Domain_name.t | `Fmt of Dks.selector ]
  }

  type t = {
      mutable seal: Arc.Sign.seal
    ; mutable msgsig: Dkim.unsigned Dkim.t
    ; mutable domain_key: Dkim.domain_key
    ; mutable key: Arc.key
    ; mutable count: int
    ; pk: private_key
    ; hash: Dkim.hash
    ; domain_name: [ `raw ] Domain_name.t
  }

  let of_cfg ~selector ~alg:algorithm ?expiration (cfg : cfg) domain_name =
    let hash = cfg.hash in
    Arc.Sign.seal ~algorithm ~hash ?expiration ~selector domain_name

  let v ?(count = 1) ~(cfg : cfg) ~msgsig ?x:expiration ~selector pk domain_name
      =
    let* key, alg = private_key ~count domain_name pk in
    let seal = of_cfg ~selector ~alg ?expiration cfg domain_name in
    let msgsig = DKIM.of_cfg ~selector ~alg ?expiration msgsig domain_name in
    let hash = cfg.hash in
    let domain_key = Dkim.domain_key_of_dkim ~key msgsig in
    Ok { seal; msgsig; domain_key; hash; pk; key; count; domain_name }
end

type cfg = DKIM of DKIM.cfg | ARC of ARC.cfg * DKIM.cfg
type t = DKIM of DKIM.t | ARC of ARC.t

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

let new_line = "\r\n"

let handler pool ~info:(sinfo, cinfo) client _dns resolver flow t =
  Cattery.use pool @@ fun v ->
  let _, (peer, port) = Mnet.TCP.peers flow in
  let ic = Miou.Computation.create () in
  let oc = Miou.Computation.create () in
  Logs.debug (fun m -> m "new client: %a:%d" Ipaddr.pp peer port);
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
    match (Miou.Computation.await_exn ic, t) with
    | m, ARC t ->
        (* NOTE(dinosaure): The objective of this branch is to:
           1) retrieve the [ARC-Set] chain so that we can complete it with our
              ARC signature
           2) sign the email with our current private key

           It should be noted that [nec] does not perform DMARC verification.
           This is done upstream (by [elit]) because [nec] should be located in
           a private network (in order to protect data relating to the private
           key and the private key itself). The email received should therefore
           have an [ARC-Authentication-Results] that is not associated with any
           [ARC-Set]s. *)
        assert (Miou.Computation.try_return oc `Ok);
        Logs.debug (fun pd ->
            pd "Receive a new email from:%a (ARC)" Colombe.Reverse_path.pp
              (fst m.Ptt.from));
        let receiver =
          match sinfo.Ptt.domain with
          | Colombe.Domain.Domain v -> `Domain v
          | IPv4 ipv4 -> `Addr (Emile.IPv4 ipv4)
          | IPv6 ipv6 -> `Addr (Emile.IPv6 ipv6)
          | Extension (k, v) -> `Addr (Emile.Ext (k, v))
        in
        let into =
          let open Flux.Sink.Syntax in
          let+ bstr = save_into v.contents and+ hdrs = headers in
          (bstr, Result.value ~default:[] hdrs)
        in
        let from = Flux.Source.bqueue q in
        let stream = Flux.Stream.from from in
        let bstr, hdrs = Flux.Stream.into into stream in
        let result =
          let chain = chain_from_headers hdrs in
          let seal = t.seal and msgsig = t.msgsig and pks = (t.key, None) in
          Logs.debug (fun m ->
              m "Sign with a new identifier: %d" (succ (List.length chain)));
          let into = arc ~seal ~msgsig ~receiver pks (`Unverified chain) in
          let from = from_bstr bstr in
          let stream = Flux.Stream.from from in
          let* set = Flux.Stream.into into stream in
          let str = Prettym.to_string ~new_line Arc.Encoder.stamp set in
          Ok str
        in
        begin match result with
        | Ok str ->
            let s0 = Flux.Stream.from (Flux.Source.list [ str ]) in
            let s1 = Flux.Stream.from (from_bstr bstr) in
            let seq = Seq.forever @@ fun () -> Flux.Stream.concat s0 s1 in
            let from = fst m.Ptt.from in
            let recipients = List.map fst m.Ptt.recipients in
            let errs =
              Facteur.sendmail client ~info:cinfo resolver ~from recipients seq
            in
            let fn (dst, err) =
              Logs.err (fun m ->
                  m "Impossible to send emails to %a: %a" Facteur.Aggregate.pp
                    dst Facteur.pp_error err)
            in
            List.iter fn errs
        | Error err ->
            Logs.err (fun m ->
                m "Impossible to sign incoming email: %a" Utils.pp_error err)
        end
    | m, DKIM t ->
        assert (Miou.Computation.try_return oc `Ok);
        Logs.debug (fun pd ->
            pd "Receive a new email from:%a (DKIM)" Colombe.Reverse_path.pp
              (fst m.Ptt.from));
        let signer = dkim ~key:t.key t.dkim in
        let into =
          let open Flux.Sink.Syntax in
          let+ bstr = save_into v.contents and+ dkim = signer in
          (bstr, dkim)
        in
        Logs.debug (fun m -> m "Start to sign incoming email");
        let from = Flux.Source.bqueue q in
        let stream = Flux.Stream.from from in
        let bstr, dkim = Flux.Stream.into into stream in
        Logs.debug (fun m -> m "Signer process terminated");
        begin match dkim with
        | Ok dkim ->
            Logs.debug (fun m -> m "Email signed");
            let bbh = Dkim.signature_and_hash dkim in
            let bbh = (bbh :> string * Dkim.hash_value) in
            let dkim = Dkim.with_signature_and_hash dkim bbh in
            let str = Prettym.to_string ~new_line Dkim.Encoder.as_field dkim in
            let s0 = Flux.Stream.from (Flux.Source.list [ str ]) in
            let s1 = Flux.Stream.from (from_bstr bstr) in
            let seq = Seq.forever @@ fun () -> Flux.Stream.concat s0 s1 in
            let from = fst m.Ptt.from in
            let recipients = List.map fst m.Ptt.recipients in
            Logs.debug (fun m -> m "send signed email");
            let errs =
              Facteur.sendmail client ~info:cinfo resolver ~from recipients seq
            in
            let fn (dst, err) =
              Logs.err (fun m ->
                  m "Impossible to send emails to %a: %a" Facteur.Aggregate.pp
                    dst Facteur.pp_error err)
            in
            List.iter fn errs
        | Error err ->
            Logs.err (fun m ->
                m "Impossible to sign incoming email: %a" Utils.pp_error err)
        end
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

let verify_and_update tcp dns primary dkim ~with_version dk =
  Logs.debug (fun m ->
      m "Verify & update with %a => %S" Domain_name.pp (Dkim.selector dkim)
        (Dkim.domain_key_to_string ~with_version dk));
  let* set = Dks.verify dns dkim dk in
  match (set, primary) with
  | true, _ -> Ok ()
  | false, Some (server, dns_key) ->
      Dks.update tcp server dns_key dkim ~with_version dk
  | false, None ->
      assert false (* NOTE(dinosaure): see [setup_post_settings]. *)

let only_verify dns dkim dk =
  match Dks.verify dns dkim dk with
  | Ok true -> Ok ()
  | Ok false ->
      error_msgf "Your domain is not well configured with the given domain-key"
  | Error _ as err -> err

let last_valid_domain_key ~now ?expiration dks =
  match (dks, expiration) with
  | [], _ -> None
  | (epoch, selector, dk) :: _, None -> Some (epoch, selector, dk)
  | (epoch, selector, dk) :: _, Some (`At than) ->
      let expired = Ptime.is_later ~than epoch in
      if expired then None else Some (epoch, selector, dk)
  | (epoch, selector, dk) :: _, Some (`For span) ->
      let than = Ptime.add_span epoch span in
      let expired = Option.map (fun than -> Ptime.is_later ~than now) than in
      if Option.value ~default:false expired then None
      else Some (epoch, selector, dk)

let selectorf (Dks.Selector { prj= fmt; _ }) =
  let now = Mirage_ptime.now () in
  let now = Ptime.to_float_s now in
  let now = int_of_float now in
  let str = Fmt.str fmt now in
  Domain_name.of_string str

let expiration_with_selectorf ?(epoch = Mirage_ptime.now ()) = function
  | Some (`At v) -> Some (Int64.of_float (Ptime.to_float_s v))
  | Some (`For span) ->
      let v = Ptime.add_span epoch span in
      let v = Option.map Ptime.to_float_s v in
      Option.map Int64.of_float v
  | None -> None

let expiration = function
  | Some (`At v) -> Some (Int64.of_float (Ptime.to_float_s v))
  | Some (`For _) ->
      Logs.warn (fun m ->
          m
            "It is impossible to annotate an expiration date in email \
             signatures based on a duration; this parameter is ignored.");
      None
  | None -> None

let get_domain_key_and_key info tcp primary (cfg : cfg) :
    (t, [> Dks.error ]) result =
  let domain_name =
    match info.Ptt.domain with
    | Colombe.Domain.IPv4 ipv4 ->
        Domain_name.raw (Ipaddr.V4.to_domain_name ipv4)
    | IPv6 ipv6 -> Domain_name.raw (Ipaddr.V6.to_domain_name ipv6)
    | Extension (k, v) -> Fmt.failwith "Impossible to handle [%s:%s]" k v
    | Domain vs ->
        let str = String.concat "." vs in
        Domain_name.of_string_exn str
  in
  match (cfg, primary) with
  | DKIM ({ pk; selector= `Fixed selector; _ } as cfg), _ ->
      let x = expiration cfg.expiration in
      let* v = DKIM.v ~count:1 ~cfg ?x ~selector pk domain_name in
      Ok (DKIM v)
  | DKIM ({ pk; selector= `Fmt self; _ } as cfg), Some (dns_server, dns_key) ->
      let* dks = Dks.domain_keys tcp dns_server dns_key domain_name in
      let dks = Dks.lint_and_sort self dks in
      let now = Mirage_ptime.now () in
      let count = List.length dks in
      Logs.debug (fun m ->
          m "Found %d domain-key(s) for our DKIM signature" count);
      begin match last_valid_domain_key ~now ?expiration:cfg.expiration dks with
      | Some (epoch, selector, _dk) ->
          Logs.debug (fun m ->
              m "found a valid and not yet expired recorded domain-key");
          let x = expiration_with_selectorf ~epoch cfg.expiration in
          let* v = DKIM.v ~count ~cfg ?x ~selector pk domain_name in
          (* assert (Dkim.equal_domain_key _dk v.ARC.domain_key) *)
          Ok (DKIM v)
      | None ->
          let* selector = selectorf self in
          let x = expiration_with_selectorf cfg.expiration in
          let count = Int.max 1 count in
          let* v = DKIM.v ~count ~cfg ?x ~selector pk domain_name in
          Ok (DKIM v)
      end
  | DKIM { selector= `Fmt _; _ }, None ->
      error_msgf
        "Impossible to configure a DKIM key without a DNS primary server"
  | ARC (({ pk; selector= `Fixed selector; _ } as cfg), msgsig), _ ->
      let x = expiration cfg.expiration in
      let* v = ARC.v ~cfg ~msgsig ?x ~selector pk domain_name in
      Ok (ARC v)
  | ( ARC (({ pk; selector= `Fmt self; _ } as cfg), msgsig)
    , Some (dns_server, dns_key) ) ->
      let* dks = Dks.domain_keys tcp dns_server dns_key domain_name in
      let dks = Dks.lint_and_sort self dks in
      let now = Mirage_ptime.now () in
      let count = List.length dks in
      Logs.debug (fun m -> m "Found %d domain-key(s) for our ARC-Set" count);
      begin match last_valid_domain_key ~now ?expiration:cfg.expiration dks with
      | Some (epoch, selector, _dk) ->
          Logs.debug (fun m ->
              m "Found a valid and not yet expired recorded domain-key");
          let x = expiration_with_selectorf ~epoch cfg.expiration in
          let* v = ARC.v ~count ~cfg ~msgsig ?x ~selector pk domain_name in
          (* assert (Dkim.equal_domain_key _dk v.DKIM.domain_key) *)
          Ok (ARC v)
      | None ->
          let* selector = selectorf self in
          let x = expiration_with_selectorf cfg.expiration in
          let count = Int.max 1 count in
          let* v = ARC.v ~count ~cfg ~msgsig ?x ~selector pk domain_name in
          Ok (ARC v)
      end
  | ARC ({ selector= `Fmt _; _ }, _), None ->
      error_msgf
        "Impossible to configure a ARC key without a DNS primary server"

(* NOTE(dinosaure): This is where we have the logic to recreate a new private
  key once the current one has expired (5 seconds before its expiry date). The
  idea is to create a task that waits for the expiry and changes the mutable
  values that are shared with our email handler (which is safe, we have only
  one core), so that the latter always has the current, unexpired private key.
 *)

let _5s = 5_000_000_000

let expiration = function
  | DKIM t -> Dkim.expire t.dkim
  | ARC t -> Arc.Sign.expire t.seal

let count = function DKIM t -> t.count | ARC _ -> assert false
let domain_name = function DKIM t -> t.domain_name | ARC t -> t.domain_name
let pk = function DKIM t -> t.pk | ARC t -> t.pk

let rec renew tcp dns primary ~expiration:span ~self t =
  let domain_name = domain_name t in
  match expiration t with
  | None -> Ok ()
  | Some sec ->
      let v = Ptime.of_float_s (Int64.to_float sec) in
      let* v = Option.to_result ~none:(msgf "Invalid expiration assigned") v in
      let v = Ptime.diff v (Mirage_ptime.now ()) in
      let v = Ptime.Span.to_int_s v |> Option.get in
      (* NOTE(dinosaure): only on 64bits architectures. It should be safe to
         cast to [int] seconds. *)
      let nsec = v * 1_000_000_000 in
      Logs.debug (fun m ->
          let nsec = Int64.of_int nsec in
          let v = Ptime.Span.of_int_s Duration.(to_sec nsec) in
          m "renew our private key in %a" Ptime.Span.pp v);
      Mkernel.sleep (nsec - _5s);
      let count = succ (count t) in
      let* key', alg = private_key ~count domain_name (pk t) in
      (* NOTE(dinosaure): we use the same private key between our [ARC-Seal]
         and our [ARC-Message-Signature]. The domain-key for our [ARC-Seal]
         **is** the domain-key for our [ARC-Message-Signature]. *)
      let* dkim', seal' =
        let expiration = Ptime.add_span (Mirage_ptime.now ()) span in
        let expiration = Option.get expiration in
        let expiration = Ptime.to_float_s expiration in
        let expiration = Int64.of_float expiration in
        let* selector = selectorf self in
        match t with
        | DKIM t ->
            let dkim' = Dkim.with_expiration t.dkim (Some expiration) in
            let dkim' = Dkim.with_selector ~selector dkim' in
            Ok (dkim', None)
        | ARC t ->
            let msgsig' = Dkim.with_expiration t.msgsig (Some expiration) in
            let msgsig' = Dkim.with_selector ~selector msgsig' in
            let algorithm = alg and hash = t.hash in
            let seal' =
              Arc.Sign.seal ~algorithm ~hash ~expiration ~selector domain_name
            in
            Ok (msgsig', Some seal')
      in
      let dk' = Dkim.domain_key_of_dkim ~key:key' dkim' in
      let with_version = match t with DKIM _ -> true | ARC _ -> false in
      let* () = verify_and_update tcp dns primary dkim' ~with_version dk' in
      begin match t with
      | ARC t ->
          t.seal <- Option.get seal';
          t.msgsig <- dkim';
          t.count <- succ t.count;
          t.domain_key <- dk';
          t.key <- key'
      | DKIM t ->
          t.dkim <- dkim';
          t.count <- succ t.count;
          t.domain_key <- dk';
          t.key <- key'
      end;
      renew tcp dns primary ~expiration:span ~self t

let renew tcp dns primary (cfg : cfg) t =
  match (cfg, primary) with
  | DKIM { selector= `Fmt self; expiration= Some (`For x); _ }, Some _
  | ARC ({ selector= `Fmt self; expiration= Some (`For x); _ }, _), Some _ ->
      let fn () = renew tcp dns primary ~expiration:x ~self t in
      let prm = Miou.async fn in
      Some prm
  | _ -> None

module RNG = Mirage_crypto_rng.Fortuna

let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
let rng = Mkernel.map rng Mkernel.[]

let run _ (cidrv4, gateway, ipv6) info nameservers destination cfg primary
    (verify, update) =
  let now = Mkernel.clock_wall in
  Mkernel.(run ~now [ rng; Mnet.stack ~name:"service" ?gateway ~ipv6 cidrv4 ])
  @@ fun rng (stack, tcp, udp) () ->
  let@ () = fun () -> Mirage_crypto_rng_mkernel.kill rng in
  let@ () = fun () -> Mnet.kill stack in
  let hed, he = Mnet_happy_eyeballs.create tcp in
  let@ () = fun () -> Mnet_happy_eyeballs.kill hed in
  let dns = Mnet_dns.create ~nameservers (udp, he) in
  let t = Mnet_dns.transport dns in
  let@ () = fun () -> Mnet_dns.Transport.kill t in
  let pool =
    Cattery.create 16 @@ fun () ->
    let encoder = Bytes.create 4096 in
    let decoder = Bytes.create 4096 in
    let queue = Ke.Rke.create Bigarray.char ~capacity:0x1000 in
    let contents = Bstr.create (fst info).Ptt.size in
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
  let resolver =
    let gethostbyname ipaddrs _ = Result.ok ipaddrs
    and getmxbyname _ mail_exchange =
      Ok (Dns.Rr_map.Mx_set.singleton { preference= 0; mail_exchange })
    in
    Ptt.Resolver { gethostbyname; getmxbyname; dns= [ destination ] }
  in
  let* t = get_domain_key_and_key (fst info) tcp primary cfg in
  let* () =
    let dkim = match t with ARC t -> t.msgsig | DKIM t -> t.dkim in
    let dk = match t with ARC t -> t.domain_key | DKIM t -> t.domain_key in
    let with_version = match t with ARC _ -> false | DKIM _ -> true in
    match (verify, update) with
    | true, true -> verify_and_update tcp dns primary dkim ~with_version dk
    | true, false -> only_verify dns dkim dk
    | false, false -> Ok ()
    | false, true ->
        assert false (* NOTE(dinosaure): see [setup_post_settings]. *)
  in
  let prm = renew tcp dns primary cfg t in
  let@ () = fun () -> Option.iter Miou.cancel prm in
  let rec go orphans listen =
    clean_up orphans;
    Logs.debug (fun m -> m "Waiting for a new connection");
    let flow = Mnet.TCP.accept tcp listen in
    let _ =
      Miou.async ~orphans @@ fun () ->
      handler pool ~info client dns resolver flow t
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
let docs_signer = "Signature configuration"

let fields =
  let doc = "List of fields to sign." in
  let field = Arg.conv Mrmime.Field_name.(of_string, pp) in
  let default =
    let open Mrmime.Field_name in
    [
      v "message-id"; v "list-id"; v "list-post"; v "from"; v "dkim-signature"
    ; v "mime-version"; v "date"; v "subject"; v "to"; v "sender"
    ]
  in
  let open Arg in
  value
  & opt_all field default
  & info [ "f"; "field" ] ~doc ~docs:docs_signer ~docv:"FIELD"

let nsec_per_day = Int64.mul 86_400L 1_000_000_000L
let ps_per_ns = 1_000L

let expiration =
  let doc = "Date on which the key must expire." in
  let parser str =
    match Ptime.of_rfc3339 str with
    | Ok (ptime, _tz, _) ->
        let than = Mirage_ptime.now () in
        if Ptime.is_earlier ptime ~than then
          error_msgf "An expiration must be in the futur"
        else Ok (`At ptime)
    | Error _ ->
        begin match Duration.of_string_exn str with
        | nsec ->
            let days = Int64.div nsec nsec_per_day in
            let rem_ns = Int64.rem nsec nsec_per_day in
            let rem_ps = Int64.mul rem_ns ps_per_ns in
            let v = (Int64.to_int days, rem_ps) in
            let v = Ptime.Span.v v in
            Ok (`For v)
        | exception _exn ->
            error_msgf
              "Invalid expiration value (must be a date or a duration): %S" str
        end
  in
  let pp ppf = function
    | `At v -> Ptime.pp_rfc3339 () ppf v
    | `For v -> Ptime.Span.pp ppf v
  in
  let ptime = Arg.conv (parser, pp) in
  let open Arg in
  value
  & opt (some ptime) None
  & info [ "x"; "expiration" ] ~doc ~docs:docs_signer ~docv:"DATE"

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
  value & opt hash `SHA256 & info [ "hash" ] ~doc ~docs:docs_signer ~docv:"HASH"

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
  & info [ "c" ] ~doc ~docs:docs_signer ~docv:"CANON[/CANON]"

let docs_private_key = "PRIVATE KEY"
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
  value
  & opt alg `ED25519
  & info [ "algorithm" ] ~doc ~docs:docs_private_key ~docv:"ALGORITHM"

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
  & info [ "p"; "password" ] ~doc ~docs:docs_private_key ~docv:"PASSWORD"

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
  value
  & opt (some key) None
  & info [ "private-key" ] ~doc ~docs:docs_private_key ~docv:"DER"

let setup_private_key pk password alg =
  match (pk, password) with
  | Some pk, None -> Ok (Private_key pk)
  | None, Some password -> Ok (PBKDF2 { password; alg })
  | Some pk, Some _ ->
      Logs.warn (fun m ->
          m "Ignore the user's password, we prefer to use the given private key");
      Ok (Private_key pk)
  | None, None ->
      error_msgf
        "A private key (from a password or a DER-encoded private key) is \
         required"

let setup_private_key =
  let open Term in
  let term = const setup_private_key $ private_key $ password $ algorithm in
  term_result ~usage:true term

let selector =
  let parser str =
    match Dks.selector str with
    | Ok selectorf -> Ok (`Fmt selectorf)
    | Error _ ->
        let* selector = Domain_name.of_string str in
        Ok (`Fixed selector)
  in
  let pp ppf = function
    | `Fixed s -> Domain_name.pp ppf s
    | `Fmt (Dks.Selector { raw; _ }) -> Fmt.string ppf raw
  in
  let doc = "The selector to use for domain keys." in
  let selector = Arg.conv (parser, pp) in
  let open Arg in
  required
  & opt (some selector) None
  & info [ "s"; "selector" ] ~doc ~docs:docs_signer ~docv:"SELECTOR"

let signer =
  let arc =
    let doc =
      "Sign incoming emails with a new ARC set (it $(b,does not) produces a \
       $(i,ARC-Authentication-Results), such field must already exist)."
    in
    Arg.info [ "with-arc" ] ~doc ~docs:docs_signer
  in
  let dkim =
    let doc = "Sign incoing emails with a DKIM signature." in
    Arg.info [ "with-dkim" ] ~doc ~docs:docs_signer
  in
  let open Arg in
  value & vflag `DKIM [ (`ARC, arc); (`DKIM, dkim) ]

let setup_dkim pk fields selector hash canonicalization expiration : cfg =
  DKIM { pk; hash; canonicalization; fields; expiration; selector }

let setup_arc pk fields selector hash canonicalization expiration : cfg =
  let msgsig =
    let pk = No_private_key in
    { DKIM.pk; hash; canonicalization; fields; expiration; selector }
  in
  let seal = { ARC.pk; hash; expiration; selector } in
  ARC (seal, msgsig)

let setup_signer signer pk fields selector hash canonicalization expiration =
  match signer with
  | `ARC -> setup_arc pk fields selector hash canonicalization expiration
  | `DKIM -> setup_dkim pk fields selector hash canonicalization expiration

let setup_signer =
  let open Term in
  const setup_signer
  $ signer
  $ setup_private_key
  $ fields
  $ selector
  $ hash
  $ canonicalization
  $ expiration

let destination =
  let doc = "The SMTP destination for all signed emails." in
  let ipaddr = Arg.conv Ipaddr.(of_string, pp) in
  let open Arg in
  required & opt (some ipaddr) None & info [ "dst" ] ~doc ~docv:"IPADDR"

let docs_primary_dns = "PRIMARY DNS SERVER"

let dns_server =
  let doc = "Address of the primary DNS server." in
  let parser str = Ipaddr.with_port_of_string ~default:53 str in
  let pp ppf (ipaddr, port) = Fmt.pf ppf "%a:%d" Ipaddr.pp ipaddr port in
  let addr = Arg.conv (parser, pp) in
  let open Arg in
  value
  & opt (some addr) None
  & info [ "dns-server" ] ~doc ~docs:docs_primary_dns ~docv:"IPADDR:PORT"

let dns_key =
  let doc = "DNS key to update the primary DNS server." in
  let parser = Dns.Dnskey.name_key_of_string in
  let pp = Fmt.using Dns.Dnskey.name_key_to_string Fmt.string in
  let key = Arg.conv (parser, pp) in
  let open Arg in
  value
  & opt (some key) None
  & info [ "dns-key" ] ~doc ~docs:docs_primary_dns ~docv:"NAME:ALGORITHM:DATA"

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

let verify_domain_key =
  let doc = "Verify that the domain has the correct domain-key." in
  let open Arg in
  value & flag & info [ "verify-domain-key" ] ~doc

let update_domain_key =
  let doc =
    "Update the domain with the new domain-key (this option requires a \
     $(b,--dns-server) and a $(b,--dns-key))."
  in
  let open Arg in
  value & flag & info [ "update-domain-key" ] ~doc

let setup_post_settings verify update primary =
  match (verify, update, primary) with
  | true, false, _ -> Ok (true, false)
  | true, true, None ->
      error_msgf
        "dns-key and dns-server are required if you would like to update your \
         zone file"
  | true, true, Some _ -> Ok (true, true)
  | false, false, _ -> Ok (false, false)
  | false, true, _ ->
      error_msgf "We must verify your zone file before updating it"

let setup_post_settings =
  let open Term in
  let term =
    const setup_post_settings
    $ verify_domain_key
    $ update_domain_key
    $ setup_dns_server
  in
  term_result ~usage:true term

let term =
  let open Term in
  const run
  $ setup_logs
  $ Mnet_cli.setup
  $ Ptt_cli.term_info
  $ setup_nameservers
  $ destination
  $ setup_signer
  $ setup_dns_server
  $ setup_post_settings

let cmd =
  let term = Term.map (Result.map_error (msgf "%a" Dks.pp_error)) term in
  let info = Cmd.info "nec" in
  Cmd.v info (Term.term_result ~usage:false term)

let () = Cmd.(exit @@ eval cmd)
