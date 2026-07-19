let src = Logs.Src.create "ptt.ca"
let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Log = (val Logs.src_log src : Logs.LOG)

let prefix =
  X509.Distinguished_name.[ Relative_distinguished_name.singleton (CN "ptt") ]

let cacert_dn =
  let open X509.Distinguished_name in
  prefix @ [ Relative_distinguished_name.singleton (CN "Ephemeral CA for ptt") ]

let cacert_lifetime = Ptime.Span.v (365, 0L)
let _10s = Ptime.Span.of_int_s 10
let ( let* ) = Result.bind

type t = X509.Certificate.t * X509.Private_key.t * X509.Authenticator.t

let make domain_name ~seed =
  let* domain_name = Domain_name.of_string domain_name in
  let* domain_name = Domain_name.host domain_name in
  let pk =
    let seed = Base64.decode_exn ~pad:false seed in
    let g = Mirage_crypto_rng.(create ~seed (module Fortuna)) in
    Mirage_crypto_pk.Rsa.generate ~g ~bits:2048 ()
  in
  let now = Mirage_ptime.now () in
  let valid_from = Option.get Ptime.(sub_span now _10s) in
  let* valid_until =
    Ptime.add_span valid_from cacert_lifetime
    |> Option.to_result ~none:(msgf "End time out of range")
  in
  let* ca_csr = X509.Signing_request.create cacert_dn (`RSA pk) in
  let extensions =
    let open X509 in
    let open X509.Extension in
    let key_id = Public_key.id Signing_request.((info ca_csr).public_key) in
    let domain_name = Domain_name.to_string domain_name in
    empty
    |> add Subject_alt_name (true, General_name.(singleton DNS [ domain_name ]))
    |> add Basic_constraints (true, (false, None))
    |> add Key_usage
         (true, [ `Digital_signature; `Content_commitment; `Key_encipherment ])
    |> add Subject_key_id (false, key_id)
  in
  let* cert =
    X509.Signing_request.sign ~valid_from ~valid_until ~extensions ca_csr
      (`RSA pk) cacert_dn
    |> Result.map_error (msgf "%a" X509.Validation.pp_signature_error)
  in
  let fingerprint = X509.Certificate.fingerprint `SHA256 cert in
  let time () = Some (Mirage_ptime.now ()) in
  let authenticator =
    X509.Authenticator.cert_fingerprint ~time ~hash:`SHA256 ~fingerprint
  in
  Ok (cert, `RSA pk, authenticator)

let self_signed info ~seed =
  let domain = Colombe.Domain.to_string info.Ptt.domain in
  let* cert, pk, _ = make domain ~seed in
  Log.info (fun m ->
      m "Using a reproducible self-signed certificate for %s" domain);
  let* tls = Tls.Config.server ~certificates:(`Single ([ cert ], pk)) () in
  Ok (tls, None)

let tls tcp info self_signed_cert cert_dns =
  match (self_signed_cert, cert_dns) with
  | None, Some ((ipaddr, port), key, key_seed) ->
      let* hostname =
        match info.Ptt.domain with
        | Colombe.Domain.Domain vs ->
            let* raw = Domain_name.of_strings vs in
            Domain_name.host raw
        | IPv4 ipv4 -> Ok (Ipaddr.V4.to_domain_name ipv4)
        | IPv6 ipv6 -> Ok (Ipaddr.V6.to_domain_name ipv6)
        | Extension _ ->
            error_msgf "Cannot request a certificate for %a" Colombe.Domain.pp
              info.Ptt.domain
      in
      let* certs, key =
        Cert.retrieve_certificate tcp key ~hostname ~key_seed ipaddr port
      in
      let not_after = snd (X509.Certificate.validity (List.hd certs)) in
      Log.info (fun m ->
          m "Certificate retrieved from %a, valid until %a" Ipaddr.pp ipaddr
            Ptime.pp not_after);
      let* tls = Tls.Config.server ~certificates:(`Single (certs, key)) () in
      Ok (tls, Some not_after)
  | Some seed, _ -> self_signed info ~seed
  | None, None ->
      Fmt.invalid_arg
        "A seed or a DNS server is required to retrive a TLS certificate"
