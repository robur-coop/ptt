let ( let* ) = Result.bind
let ( let@ ) finally fn = Fun.protect ~finally fn
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let src = Logs.Src.create "dks"

module Log = (val Logs.src_log src : Logs.LOG)

type error =
  [ `Bad_reply of Dns.Packet.mismatch * Dns.Packet.t
  | `Decode of Dns.Packet.err
  | `Msg of string
  | `No_tlsa
  | `Tsig of Dns_tsig.e
  | `Unexpected_reply of Dns.Packet.reply ]

let send flow answer =
  let _, (dst, port) = Mnet.TCP.peers flow in
  try
    let len = Bytes.create 2 in
    Bytes.set_uint16_be len 0 (String.length answer);
    Mnet.TCP.write flow (Bytes.to_string len);
    Mnet.TCP.write flow answer;
    Ok ()
  with exn ->
    error_msgf "Impossible to write DNS packet to %a:%d: %s" Ipaddr.pp dst port
      (Printexc.to_string exn)

let recv flow =
  try
    let len = Bytes.create 2 in
    Mnet.TCP.really_read flow len;
    let len = Bytes.get_uint16_be len 0 in
    let buf = Bytes.create len in
    Mnet.TCP.really_read flow buf;
    Ok (Bytes.unsafe_to_string buf)
  with exn ->
    let _, (dst, port) = Mnet.TCP.peers flow in
    error_msgf "Impossible to read DNS packet from %a:%d: %s" Ipaddr.pp dst port
      (Printexc.to_string exn)

let gen = Mirage_crypto_rng.generate
let now = Mirage_ptime.now
let _2s = 2_000_000_000

let nsupdate_csr flow host keyname zone dnskey csr =
  let* out, fn = Dns_certify.nsupdate gen now ~host ~keyname ~zone dnskey csr in
  let* () = send flow out in
  let* data = recv flow in
  fn data

let query_certificate flow name csr =
  let* out, fn = Dns_certify.query gen (now ()) name csr in
  let* () = send flow out in
  let* data = recv flow in
  fn data

let query_certificate_or_csr flow hostname keyname zone dnskey csr =
  match query_certificate flow hostname csr with
  | Ok _ as value -> value
  | Error (`Msg _) as err -> err
  | Error (`Decode _ | `Bad_reply _ | `Unexpected_reply _) ->
      error_msgf "Query error"
  | Error `No_tlsa ->
      let* () = nsupdate_csr flow hostname keyname zone dnskey csr in
      let rec wait_for_cert ?(retry = 10) () =
        if retry <= 0 then error_msgf "Too many retries, giving up"
        else begin
          Log.debug (fun m -> m "Asking for our certificate");
          match query_certificate flow hostname csr with
          | Ok _ as value -> value
          | Error #Dns_certify.q_err ->
              Mkernel.sleep _2s;
              wait_for_cert ~retry:(retry - 1) ()
          | Error _ as err -> err
        end
      in
      wait_for_cert ()

let retrieve_certificate tcp (dns_key_name, dns_key) ~hostname
    ?additional_hostnames:(more_hostnames = []) ?(key_type = `RSA) ?key_data
    ?key_seed ?bits dns port =
  let zone = Domain_name.(host_exn (drop_label_exn ~amount:2 dns_key_name)) in
  let not_sub subdomain =
    not (Domain_name.is_subdomain ~subdomain ~domain:zone)
  in
  if not_sub hostname then
    Fmt.invalid_arg "%a is not a subdomain of zone provided by your DNS key"
      Domain_name.pp hostname;
  let key =
    let seed_or_data, data =
      match (key_data, key_seed) with
      | None, None -> invalid_arg "Neither key data nor key seed is supplied"
      | Some data, _ -> (Some `Data, data)
      | None, Some seed -> (Some `Seed, seed)
    in
    let ok = Fun.id
    and error (`Msg msg) = Fmt.invalid_arg "Key generation failed: %s" msg in
    X509.Private_key.of_string ?seed_or_data ?bits key_type data
    |> Result.fold ~ok ~error
  in
  let* csr = Dns_certify.signing_request hostname ~more_hostnames key in
  let flow = Mnet.TCP.connect tcp (dns, port) in
  let finally = Mnet.TCP.close in
  let res = Miou.Ownership.create ~finally flow in
  Miou.Ownership.own res;
  let@ () = fun () -> Miou.Ownership.release res in
  let* cert, chain =
    query_certificate_or_csr flow hostname dns_key_name zone dns_key csr
  in
  Ok (cert :: chain, key)
