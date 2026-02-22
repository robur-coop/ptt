let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt

let prefix =
  X509.Distinguished_name.[ Relative_distinguished_name.singleton (CN "ptt") ]

let cacert_dn =
  let open X509.Distinguished_name in
  prefix @ [ Relative_distinguished_name.singleton (CN "Ephemeral CA for ptt") ]

let cacert_lifetime = Ptime.Span.v (365, 0L)
let _10s = Ptime.Span.of_int_s 10
let ( let* ) = Result.bind

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
