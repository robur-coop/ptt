let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

type error =
  [ Dmarc.Verify.error
  | `Invalid_email
  | `Not_enough
  | `Invalid_domain_key of Arc.t
  | `Missing_authentication_results ]

let pp_error ppf = function
  | #Dmarc.Verify.error as err -> Dmarc.Verify.pp_error ppf err
  | `Not_enough -> Fmt.string ppf "Email truncated"
  | `Invalid_domain_key _ -> Fmt.string ppf "Invalid domain key"
  | `Missing_authentication_results ->
      Fmt.string ppf "Missing authentication results"

type dmarc = Dmarc.Verify.info * Dmarc.DKIM.t list * [ `Fail | `Pass ]

let dmarc ~ctx dns =
  let rec until_await decoder =
    match Dmarc.Verify.decode decoder with
    | #Dmarc.Verify.error as err -> `Error err
    | `Info value -> `Ok value
    | `Query (decoder, domain_name, Dns.Rr_map.K record) ->
        let resp = Mnet_dns.get_resource_record dns record domain_name in
        until_await (Dmarc.Verify.response decoder record resp)
    | `Await decoder -> `Continue decoder
  in
  let rec until_info decoder =
    match Dmarc.Verify.decode decoder with
    | #Dmarc.Verify.error as err -> Error err
    | `Info value -> Ok value
    | `Query (decoder, domain_name, Dns.Rr_map.K record) ->
        let resp = Mnet_dns.get_resource_record dns record domain_name in
        until_info (Dmarc.Verify.response decoder record resp)
    | `Await _decoder -> Error `Not_enough
  in
  let init () = `Continue (Dmarc.Verify.decoder ~ctx ())
  and push acc str =
    match acc with
    | `Continue decoder when String.length str > 0 ->
        let len = String.length str in
        let decoder = Dmarc.Verify.src decoder str 0 len in
        until_await decoder
    | (`Continue _ | `Ok _ | `Error _) as value -> value
  and full _ = false
  and stop = function
    | `Ok value -> Ok value
    | `Error err -> Error err
    | `Continue decoder ->
        let decoder = Dmarc.Verify.src decoder String.empty 0 0 in
        until_info decoder
  in
  Flux.Sink { init; push; full; stop }

let dkim ~key v =
  let init () = `Await (Dkim.Sign.signer ~key v)
  and push state str =
    match state with
    | `Await signer when String.length str > 0 ->
        Logs.debug (fun m -> m "Sign +%d byte(s)" (String.length str));
        let signer = Dkim.Sign.fill signer str 0 (String.length str) in
        Dkim.Sign.sign signer
    | `Await _ | `Malformed _ | `Signature _ -> state
  and full = Fun.const false in
  let rec stop = function
    | `Malformed _ ->
        Logs.err (fun m -> m "Invalid email according to our signer");
        Error `Invalid_email
    | `Signature v ->
        Logs.debug (fun m -> m "Signer terminated properly");
        Ok v
    | `Await signer ->
        Logs.debug (fun m -> m "Stop signing");
        let signer = Dkim.Sign.fill signer String.empty 0 0 in
        stop (Dkim.Sign.sign signer)
  in
  Flux.Sink { init; push; full; stop }

let request dns domain_name =
  let resp = Mnet_dns.getaddrinfo dns Dns.Rr_map.Txt domain_name in
  match resp with
  | Ok (_ttl, txts) ->
      let txts = Dns.Rr_map.Txt_set.elements txts in
      let txts =
        List.map
          (Fun.compose (String.concat "") (String.split_on_char ' '))
          txts
      in
      let txts = String.concat "" txts in
      begin match Dkim.domain_key_of_string txts with
      | Ok dk -> (domain_name, `Domain_key dk)
      | Error (`Msg msg) -> (domain_name, `DNS_error msg)
      end
  | Error (`Msg msg) -> (domain_name, `DNS_error msg)

let requests dns queries =
  let fn domain_name = Miou.async @@ fun () -> request dns domain_name in
  let tbl = Array.of_list queries in
  let prms = List.map fn queries in
  let results = Miou.await_all prms in
  let fn idx = function
    | Ok value -> value
    | Error exn ->
        let msg = Fmt.str "Unexpected exception: %s" (Printexc.to_string exn) in
        (tbl.(idx), `DNS_error msg)
  in
  List.mapi fn results

let chain dns =
  let rec until_await decoder =
    match Arc.Verify.decode decoder with
    | `Queries (decoder, set) ->
        begin match Arc.Verify.queries set with
        | Error _ -> `Error (`Invalid_domain_key set)
        | Ok queries ->
            let responses = requests dns queries in
            let decoder = Arc.Verify.response decoder responses in
            let decoder = Result.get_ok decoder in
            (* NOTE(dinosaure): should be safe. *)
            until_await decoder
        end
    | `Malformed msg ->
        Logs.err (fun m -> m "Malformed email: %s" msg);
        `Error `Invalid_email
    | `Chain chain -> `Ok chain
    | `Await decoder -> `Continue decoder
  in
  let rec until_chain decoder =
    match Arc.Verify.decode decoder with
    | `Queries (decoder, set) ->
        begin match Arc.Verify.queries set with
        | Error _ -> Error (`Invalid_domain_key set)
        | Ok queries ->
            let responses = requests dns queries in
            let decoder = Arc.Verify.response decoder responses in
            let decoder = Result.get_ok decoder in
            (* NOTE(dinosaure): should be safe. *)
            until_chain decoder
        end
    | `Malformed msg ->
        Logs.err (fun m -> m "Malformed email: %s" msg);
        Error `Invalid_email
    | `Chain chain -> Ok chain
    | `Await _ -> assert false
  in
  let init () = `Continue (Arc.Verify.decoder ())
  and push state str =
    match state with
    | `Continue decoder when String.length str > 0 ->
        let decoder = Arc.Verify.src decoder str 0 (String.length str) in
        until_await decoder
    | `Continue _ | `Ok _ | `Error _ -> state
  and full _ = false
  and stop = function
    | `Error err -> Error err
    | `Ok chain -> Ok chain
    | `Continue decoder ->
        let decoder = Arc.Verify.src decoder String.empty 0 0 in
        until_chain decoder
  in
  Flux.Sink { init; push; full; stop }

let arc ~seal ~msgsig ~receiver ?results keys chain =
  let signer = Arc.Sign.signer ~seal ~msgsig ~receiver ?results keys chain in
  let init = Fun.const (`Await signer)
  and push state str =
    match state with
    | `Await t when String.length str > 0 ->
        let t = Arc.Sign.fill t str 0 (String.length str) in
        Arc.Sign.sign t
    | `Await _ | `Set _ | `Malformed _ | `Missing_authentication_results ->
        state
  and full = function `Await _ -> false | _ -> true in
  let rec stop = function
    | `Await t ->
        let t = Arc.Sign.fill t String.empty 0 0 in
        stop (Arc.Sign.sign t)
    | `Set set -> Ok set
    | `Malformed msg ->
        Logs.err (fun m -> m "Malformed email: %s" msg);
        Error `Invalid_email
    | `Missing_authentication_results -> Error `Missing_authentication_results
  in
  Flux.Sink { init; push; full; stop }

type field = Mrmime.Field_name.t * Unstrctrd.t

let p =
  let open Mrmime in
  let unstructured = Field.(Witness Unstructured) in
  let open Field_name in
  Map.empty
  |> Map.add date unstructured
  |> Map.add from unstructured
  |> Map.add sender unstructured
  |> Map.add reply_to unstructured
  |> Map.add (v "To") unstructured
  |> Map.add cc unstructured
  |> Map.add bcc unstructured
  |> Map.add subject unstructured
  |> Map.add message_id unstructured
  |> Map.add comments unstructured
  |> Map.add content_type unstructured
  |> Map.add content_encoding unstructured

let to_unstrctrd : type a. a Mrmime.Field.t -> a -> Unstrctrd.t =
 fun w v ->
  match w with
  | Mrmime.Field.Unstructured ->
      let fold acc = function
        | #Unstrctrd.elt as elt -> elt :: acc
        | _ -> acc
      in
      let unstrctrd = List.fold_left fold [] v in
      Result.get_ok (Unstrctrd.of_list (List.rev unstrctrd))
  | _ -> assert false

let headers =
  let open Mrmime in
  let rec until_await fields decoder =
    match Hd.decode decoder with
    | `Field field ->
        let (Field.Field (fn, w, v)) = Location.prj field in
        let value = to_unstrctrd w v in
        until_await ((fn, value) :: fields) decoder
    | `Malformed _ -> `Error `Invalid_email
    | `End _prelude -> `Ok (List.rev fields)
    | `Await -> `Continue (fields, decoder)
  in
  let rec until_end fields decoder =
    match Hd.decode decoder with
    | `Field field ->
        let (Field.Field (fn, w, v)) = Location.prj field in
        let value = to_unstrctrd w v in
        until_end ((fn, value) :: fields) decoder
    | `Malformed _ -> Error `Invalid_email
    | `End _prelude -> Ok (List.rev fields)
    | `Await -> Error `Not_enough
  in
  let init () = `Continue ([], Hd.decoder p)
  and push acc str =
    match acc with
    | `Continue (fields, decoder) when String.length str > 0 ->
        let len = String.length str in
        Hd.src decoder str 0 len; until_await fields decoder
    | (`Continue _ | `Ok _ | `Error _) as value -> value
  and full _ = false
  and stop = function
    | `Ok value -> Ok value
    | `Error err -> Error err
    | `Continue (fields, decoder) ->
        Hd.src decoder String.empty 0 0;
        until_end fields decoder
  in
  Flux.Sink { init; push; full; stop }

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

let from_bstr ?(len = 0x7ff) bstr =
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

let get_identifier_from_signature unstrctrd =
  let ( let* ) = Result.bind in
  let* m = Dkim.of_unstrctrd_to_map unstrctrd in
  let none = msgf "Missing i field" in
  let* i = Option.to_result ~none (Dkim.get_key "i" m) in
  match int_of_string_opt i with
  | Some i -> Ok i
  | None -> error_msgf "Invalid ARC signature"

let get_identifier_from_authentication_results =
  let parser =
    let open Angstrom in
    let p = Dmarc.Authentication_results.Decoder.authres_payload in
    let is_white = function ' ' | '\t' -> true | _ -> false in
    let is_digit = function '0' .. '9' -> true | _ -> false in
    let ignore_spaces = skip_while is_white in
    ignore_spaces
    *> string "i"
    *> ignore_spaces
    *> char '='
    *> ignore_spaces
    *> take_while1 is_digit
    >>= fun uid ->
    ignore_spaces *> char ';' >>= fun _ ->
    p >>= fun _ -> return (int_of_string uid)
  in
  fun unstrctrd ->
    let ( let* ) = Result.bind in
    let v = Unstrctrd.fold_fws unstrctrd in
    let* v = Unstrctrd.without_comments v in
    let str = Unstrctrd.to_utf_8_string v in
    match Angstrom.parse_string ~consume:All parser str with
    | Ok uid -> Ok uid
    | Error _ -> error_msgf "Invalid ARC authentication results"

let compare_arc_fields a b =
  match (a, b) with
  | (a, _, _, _), (b, _, _, _) when a <> b -> Int.compare a b
  | (_, `Results, _, _), (_, `Results, _, _) -> 0
  | (_, `Results, _, _), _ -> -1
  | (_, `Msgsig, _, _), (_, `Msgsig, _, _) -> 0
  | (_, `Msgsig, _, _), (_, `Seal, _, _) -> -1
  | (_, `Seal, _, _), (_, `Seal, _, _) -> 0
  | _, _ -> 1

let is_arc_seal = Mrmime.Field_name.(equal (v "ARC-Seal"))

let is_arc_message_signature =
  Mrmime.Field_name.(equal (v "ARC-Message-Signature"))

let is_arc_authentication_results =
  Mrmime.Field_name.(equal (v "ARC-Authentication-Results"))

let chain_from_headers hdrs =
  let fn (field_name, unstrctrd) =
    if is_arc_seal field_name then
      match get_identifier_from_signature unstrctrd with
      | Ok uid -> Some (uid, `Seal, field_name, unstrctrd)
      | Error _ -> None
    else if is_arc_message_signature field_name then
      match get_identifier_from_signature unstrctrd with
      | Ok uid -> Some (uid, `Msgsig, field_name, unstrctrd)
      | Error _ -> None
    else if is_arc_authentication_results field_name then
      match get_identifier_from_authentication_results unstrctrd with
      | Ok uid -> Some (uid, `Results, field_name, unstrctrd)
      | Error _ -> None
    else None
  in
  let chain = List.filter_map fn hdrs in
  let chain = List.sort compare_arc_fields chain in
  let rec aggregate sets = function
    | [] -> sets
    | (u0, `Results, f0, v0)
      :: (u1, `Msgsig, f1, v1)
      :: (u2, `Seal, f2, v2)
      :: rest ->
        if u0 = u1 && u1 = u2 then
          aggregate (((f0, v0), (f1, v1), (f2, v2)) :: sets) rest
        else aggregate sets rest
    | _ :: rest -> aggregate sets rest
  in
  aggregate [] chain
