let ( let* ) = Result.bind
let ( let@ ) finally fn = Fun.protect ~finally fn
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

type error =
  [ `Msg of string
  | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
  | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t
  | Dns_tsig.s
  | Dns_tsig.e
  | Dns.Packet.mismatch ]

let pp_error ppf = function
  | `Msg msg -> Fmt.string ppf msg
  | `No_data (domain_name, _soa) ->
      Fmt.pf ppf "No DNS record for %a" Domain_name.pp domain_name
  | `No_domain (domain_name, _soa) ->
      Fmt.pf ppf "%a not found" Domain_name.pp domain_name
  | #Dns_tsig.s as s -> Dns_tsig.pp_s ppf s
  | #Dns_tsig.e as e -> Dns_tsig.pp_e ppf e
  | #Dns.Packet.mismatch as m -> Dns.Packet.pp_mismatch ppf m

let verify dns dkim dk =
  let* domain_name = Dkim.Verify.domain_key dkim in
  match Mnet_dns.get_resource_record dns Dns.Rr_map.Txt domain_name with
  | Error (`No_data _) -> Ok false
  | Error (`No_domain _) -> Ok false
  | Error (`Msg msg) -> Error (`Msg msg)
  | Ok (_, sstr) ->
      let sstr = Dns.Rr_map.Txt_set.elements sstr in
      let str = String.concat "" sstr in
      let* dk' = Dkim.domain_key_of_string str in
      let expired = Option.map Int64.to_float (Dkim.expire dkim) in
      let expired = Option.map Ptime.of_float_s expired in
      let expired = Option.join expired in
      let than = Mirage_ptime.now () in
      let expired = Option.map (Ptime.is_later ~than) expired in
      let expired = Option.value ~default:false expired in
      Ok (Dkim.equal_domain_key dk dk' && not expired)

let domain_keys tcp dns_server (dns_key_name, dns_key) domain_name =
  let flags = Dns.Packet.Flags.empty in
  let uid = Randomconv.int16 Mirage_crypto_rng.generate in
  let question = (Domain_name.raw domain_name, `Axfr) in
  let pkt = Dns.Packet.create (uid, flags) question `Axfr_request in
  let proto = `Tcp in
  let* data, mac =
    Dns_tsig.encode_and_sign ~proto pkt (Mirage_ptime.now ()) dns_key
      dns_key_name
    |> Result.map_error @@ function #Dns_tsig.s as err -> err
  in
  let flow = Mnet.TCP.connect tcp dns_server in
  let@ () = fun () -> Mnet.TCP.close flow in
  let len = Bytes.create 2 in
  Bytes.set_uint16_be len 0 (String.length data);
  let len = Bytes.unsafe_to_string len in
  Mnet.TCP.write flow len;
  Mnet.TCP.write flow data;
  let len = Bytes.create 2 in
  Mnet.TCP.really_read flow ~len:2 len;
  let len = Bytes.get_uint16_be len 0 in
  let buf = Bytes.create len in
  Mnet.TCP.really_read flow ~len buf;
  let str = Bytes.unsafe_to_string buf in
  let* pkt', _, _ =
    Dns_tsig.decode_and_verify (Mirage_ptime.now ()) dns_key dns_key_name ~mac
      str
    |> Result.map_error @@ function #Dns_tsig.e as err -> err
  in
  match Dns.Packet.reply_matches_request ~request:pkt pkt' with
  | Ok (`Axfr_reply (_soa, m)) ->
      let domain = Domain_name.prepend_label_exn domain_name "_domainkey" in
      let fn subdomain m acc =
        match Dns.Rr_map.find Dns.Rr_map.Txt m with
        | Some (_ttl, txts) when Domain_name.is_subdomain ~subdomain ~domain ->
            let txts = Dns.Rr_map.Txt_set.to_list txts in
            let txts = String.concat "" txts in
            let selector = Domain_name.get_label_exn subdomain 0 in
            let result =
              let* dk = Dkim.domain_key_of_string txts in
              let* selector = Domain_name.of_string selector in
              Ok (selector, dk)
            in
            let ok binding = binding :: acc in
            let error _err =
              Logs.warn (fun m ->
                  m "Invalid domain-key for %a, ignore it" Domain_name.pp domain);
              acc
            in
            Result.fold ~ok ~error result
        | _ -> acc
      in
      Ok (Domain_name.Map.fold fn m [])
  | Ok _ -> error_msgf "Unexpected DNS reply"
  | Error (#Dns.Packet.mismatch as err) -> Error err

let _update = ( = ) "_update"

let update tcp dns_server (dns_key_name, dns_key) dkim dk =
  let* zone =
    match Domain_name.find_label dns_key_name _update with
    | None -> error_msgf "The given DNS key does not update a zone"
    | Some idx ->
        let amount = succ idx in
        let zone =
          Domain_name.(host_exn (drop_label_exn ~amount dns_key_name))
        in
        let* zone' = Dkim.domain_name dkim in
        if Domain_name.equal zone zone' then
          error_msgf
            "The domain of the DKIM value is not aligned with the one to update"
        else Ok zone
  in
  let* selector = Dkim.domain_name dkim in
  let flow = Mnet.TCP.connect tcp dns_server in
  let@ () = fun () -> Mnet.TCP.close flow in
  let txts = Dns.Rr_map.Txt_set.singleton (Dkim.domain_key_to_string dk) in
  let value = Dns.Packet.Update.Add Dns.Rr_map.(B (Txt, (3600l, txts))) in
  let value = Domain_name.Map.(empty, singleton selector [ value ]) in
  let flags = Dns.Packet.Flags.empty in
  let uid = Randomconv.int16 Mirage_crypto_rng.generate in
  let zone = Dns.Packet.Question.create zone Dns.Rr_map.Soa in
  let pkt = Dns.Packet.create (uid, flags) zone (`Update value) in
  let proto = `Tcp in
  let* data, mac =
    Dns_tsig.encode_and_sign ~proto pkt (Mirage_ptime.now ()) dns_key
      dns_key_name
    |> Result.map_error @@ function #Dns_tsig.s as err -> err
  in
  let len = Bytes.create 2 in
  Bytes.set_uint16_be len 0 (String.length data);
  let len = Bytes.unsafe_to_string len in
  Mnet.TCP.write flow len;
  Mnet.TCP.write flow data;
  let len = Bytes.create 2 in
  Mnet.TCP.really_read flow ~len:2 len;
  let len = Bytes.get_uint16_be len 0 in
  let buf = Bytes.create len in
  Mnet.TCP.really_read flow ~len buf;
  let str = Bytes.unsafe_to_string buf in
  let* pkt', _, _ =
    Dns_tsig.decode_and_verify (Mirage_ptime.now ()) dns_key dns_key_name ~mac
      str
    |> Result.map_error @@ function #Dns_tsig.e as err -> err
  in
  match Dns.Packet.reply_matches_request ~request:pkt pkt' with
  | Ok _ -> Ok ()
  | Error (#Dns.Packet.mismatch as err) -> Error err

type selector = Selector : { prj: prj; inj: inj; raw: string } -> selector
and prj = (int -> string, Format.formatter, unit, string) format4
and inj = (int -> int, Scanf.Scanning.scanbuf, (int -> int) -> int, int) format4

let lint_and_sort (Selector { inj; _ }) dks =
  let fn (selector, dk) =
    match Scanf.sscanf (Domain_name.to_string selector) inj Fun.id with
    | epoch ->
        let epoch = Ptime.of_float_s (float_of_int epoch) in
        Option.map (fun epoch -> (epoch, selector, dk)) epoch
    | exception _ -> None
  in
  let dks = List.filter_map fn dks in
  let fn (a, _, _) (b, _, _) = Ptime.compare b a in
  List.sort_uniq fn dks

let selector str =
  try
    let prj = CamlinternalFormat.format_of_string_format str "%d" in
    let inj = Scanf.format_from_string str "%d" in
    Ok (Selector { inj; prj; raw= str })
  with _exn -> error_msgf "Invalid selector format"
