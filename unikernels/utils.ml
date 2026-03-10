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
  let init = Fun.const (`Await (Dkim.Sign.signer ~key v))
  and push state str =
    match state with
    | `Await signer when String.length str > 0 ->
        let signer = Dkim.Sign.fill signer str 0 (String.length str) in
        Dkim.Sign.sign signer
    | `Await _ | `Malformed _ | `Signature _ -> state
  and full = function
    | `Await _ -> false
    | `Malformed _ | `Signature _ -> true
  in
  let rec stop = function
    | `Malformed _ -> Error `Invalid_email
    | `Signature v -> Ok v
    | `Await signer ->
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
    | `Queries (decoder, set) -> begin
        match Arc.Verify.queries set with
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
    | `Queries (decoder, set) -> begin
        match Arc.Verify.queries set with
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
