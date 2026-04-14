let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let src = Logs.Src.create "ptt.temp"

module Log = (val Logs.src_log src : Logs.LOG)

module Key = struct
  include Mrmime.MessageID

  let hash = Hashtbl.hash
end

module Value = struct
  type t = {
      from: Colombe.Path.t
    ; recipient: Colombe.Path.t
    ; messageID: Mrmime.MessageID.t
    ; size: int
    ; send_at: Ptime.t
    ; attempt: int
    ; counter: int
  }

  let weight { size; _ } = size

  let json =
    let address =
      let enc path = Emile.to_string (Colombe_emile.of_path path) in
      let dec str =
        match Emile.of_string str with
        | Ok mailbox -> Colombe_emile.to_path mailbox
        | Error _ -> Fmt.failwith "Invalid email address: %S" str
      in
      Jsont.map ~dec ~enc Jsont.string
    in
    let messageID =
      let enc (local, (domain : Mrmime.MessageID.domain)) =
        let domain = (domain :> Emile.domain) in
        let mailbox = { Emile.name= None; local; domain= (domain, []) } in
        Emile.to_string mailbox
      in
      let dec str =
        match Emile.of_string str with
        | Ok { local; domain= (#Mrmime.MessageID.domain as domain), []; _ } ->
            (local, domain)
        | Ok v -> Fmt.failwith "Invalid Message-ID: %a" Emile.pp_mailbox v
        | Error _ -> Fmt.failwith "Invalid Message-ID: %S" str
      in
      Jsont.map ~dec ~enc Jsont.string
    in
    let ptime =
      let enc t = Ptime.to_rfc3339 t in
      let dec str =
        match Ptime.of_rfc3339 str with
        | Ok (t, _, _) -> t
        | Error _ -> Fmt.failwith "Invalid RFC3339 date: %S" str
      in
      Jsont.map ~enc ~dec Jsont.string
    in
    let fn from recipient messageID size send_at attempt counter =
      { from; recipient; messageID; size; send_at; attempt; counter }
    in
    let open Jsont in
    Object.map fn
    |> Object.mem "from" ~enc:(fun t -> t.from) address
    |> Object.mem "recipient" ~enc:(fun t -> t.recipient) address
    |> Object.mem "messageID" ~enc:(fun t -> t.messageID) messageID
    |> Object.mem "size" ~enc:(fun t -> t.size) int
    |> Object.mem "send_at" ~enc:(fun t -> t.send_at) ptime
    |> Object.mem "attempt" ~enc:(fun t -> t.attempt) int
    |> Object.mem "counter" ~enc:(fun t -> t.counter) int
    |> Object.finish
end

module Cache = Lru.M.Make (Key) (Value)

type 'fs t = {
    get: 'fs -> Mrmime.MessageID.t -> string
  ; add: 'fs -> Mrmime.MessageID.t -> string -> unit
  ; rem: 'fs -> Mrmime.MessageID.t -> unit
  ; entries: Cache.t
  ; store: 'fs t -> unit
  ; bounces: Bounces.t
  ; fs: 'fs
  ; info: Facteur.info
  ; client: Facteur.t
  ; resolver: Ptt.resolver
}

type entry = Value.t = {
    from: Colombe.Path.t
  ; recipient: Colombe.Path.t
  ; messageID: Mrmime.MessageID.t
  ; size: int
  ; send_at: Ptime.t
  ; attempt: int
  ; counter: int
}

type 'fs action = {
    get: 'fs -> Mrmime.MessageID.t -> string
  ; add: 'fs -> Mrmime.MessageID.t -> string -> unit
  ; rem: 'fs -> Mrmime.MessageID.t -> unit
}

let _20MB = 2621440
let _15m = Ptime.Span.of_int_s 900

let create ~info ?(store = ignore) client resolver fs action bounces =
  let entries = Cache.create _20MB in
  let { get; add; rem } = action in
  { get; add; rem; entries; store; bounces; fs; info; client; resolver }

let list = Jsont.list Value.json

let json ~info ?(store = ignore) client resolver fs action bounces =
  let entries =
    let dec lst =
      let entries = Cache.create _20MB in
      let fn ({ Value.messageID; _ } as entry) =
        Cache.add messageID entry entries
      in
      List.iter fn lst; entries
    in
    let enc entries =
      let fn _k entry acc = entry :: acc in
      Cache.fold fn [] entries
    in
    Jsont.map ~enc ~dec (Jsont.list Value.json)
  in
  let enc { entries; _ } = entries in
  let dec entries =
    let { get; add; rem } = action in
    { get; add; rem; entries; store; bounces; fs; info; client; resolver }
  in
  Jsont.map ~enc ~dec entries

(* TODO(dinosaure): duplicate of unikernels/utils.ml. *)
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

let messageID ?g t =
  let now = Mirage_ptime.now () in
  let now = Ptime.to_float_s now in
  let now = Int64.of_float now in
  let seed = Mirage_crypto_rng.generate ?g 16 in
  let uuid = Uuidm.v4 (Bytes.of_string seed) in
  let uuid = Uuidm.to_string uuid in
  let local = Fmt.str "%Ld.%s" now uuid in
  let str = Fmt.str "<%s@%s>" local (Colombe.Domain.to_string t.info.domain) in
  Mrmime.MessageID.of_string str |> Result.get_ok

let add_new_failure t ~counter ~from recipient str =
  let messageID =
    let from = Flux.Source.list [ str ] in
    let via = Flux.Flow.identity in
    let into = headers in
    let result, _ = Flux.Stream.run ~from ~via ~into in
    let fn hdrs =
      let fn (field_name, _) =
        Mrmime.Field_name.(equal message_id) field_name
      in
      match List.find_opt fn hdrs with
      | Some (_, unstrctrd) -> Ok unstrctrd
      | None -> error_msgf "Missing Message-ID field"
    in
    let result = Result.bind result fn in
    let fn unstrctrd =
      let str = Unstrctrd.to_utf_8_string unstrctrd in
      Mrmime.MessageID.of_string str
    in
    let result = Result.bind result fn in
    match result with Ok messageID -> messageID | Error _ -> messageID t
  in
  let now = Mirage_ptime.now () in
  let send_at = Option.get (Ptime.add_span now _15m) in
  let size = String.length str in
  let attempt = 0 in
  let entry =
    { Value.from; recipient; messageID; size; send_at; attempt; counter }
  in
  Log.debug (fun m ->
      m "Add %a as a message to re-send later (%a)" Mrmime.MessageID.pp
        messageID (Ptime.pp_rfc3339 ()) send_at);
  Cache.add messageID entry t.entries;
  t.add t.fs messageID str;
  let rec trim () =
    if Cache.weight t.entries > Cache.capacity t.entries then
      match Cache.lru t.entries with
      | Some (messageID, _) ->
          Log.warn (fun m ->
              m "Remove %a, too old and we need free space" Mrmime.MessageID.pp
                messageID);
          t.rem t.fs messageID;
          Cache.remove messageID t.entries;
          trim ()
      | None -> ()
  in
  trim (); t.store t

let rec collect entries t =
  let than = Mirage_ptime.now () in
  match Cache.lru t.entries with
  | Some ((messageID, { Value.send_at; _ }) as entry)
    when Ptime.is_earlier send_at ~than ->
      Cache.remove messageID t.entries;
      collect (entry :: entries) t
  | _ -> List.rev entries

let collect t = collect [] t

let wait t =
  let fn _ { Value.send_at; _ } = function
    | None -> Some send_at
    | Some than when Ptime.is_earlier send_at ~than -> Some send_at
    | Some _ as value -> value
  in
  match Cache.fold fn None t.entries with
  | None ->
      Log.debug (fun m -> m "Wait 15m (no mails)");
      Mkernel.sleep 900_000_000_000 (* 15m *)
  | Some b ->
      let a = Mirage_ptime.now () in
      let diff = Ptime.diff a b in
      let secs = Ptime.Span.to_float_s diff in
      if secs > -0.0 then begin
        let nsecs = secs *. 1e9 in
        let nsecs = Int64.of_float nsecs in
        Log.debug (fun m -> m "Wait %a" Duration.pp nsecs);
        let nsecs = Int64.to_int nsecs in
        Mkernel.sleep nsecs
      end

let launch t =
  let rec go () =
    let entries = collect t in
    let fn (messageID, value) =
      let str = t.get t.fs messageID in
      let from = Flux.Source.list [ str ] in
      let seq = Seq.forever @@ fun () -> Flux.Stream.from from in
      let rcpts = [ Colombe.Forward_path.Forward_path value.Value.recipient ] in
      let result =
        let from = Some value.Value.from in
        Facteur.sendmail t.client ~info:t.info t.resolver ~from rcpts seq
      in
      match result with
      | [] ->
          t.rem t.fs messageID;
          Cache.remove messageID t.entries;
          t.store t
      | (_, err) :: _ ->
          Log.err (fun m ->
              m "Get an error while sending email to %a: %a" Colombe.Path.pp
                value.Value.recipient Facteur.pp_error err);
          let counter = value.Value.counter in
          let rcpt = value.Value.recipient in
          Bounces.failure_for_without_deletion t.bounces ~counter rcpt;
          t.rem t.fs messageID;
          Cache.remove messageID t.entries;
          t.store t
    in
    List.iter fn entries; wait t; go ()
  in
  go ()
