let src = Logs.Src.create "mlm"
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let ( let* ) = Result.bind

module Log = (val Logs.src_log src : Logs.LOG)

(* Follow RFC 5321 *)
let local_to_string local =
  let local = Colombe_emile.to_local local in
  Colombe.Path.Encoder.local_to_string local

let local_of_string str =
  let result =
    Angstrom.parse_string ~consume:All Colombe.Path.Decoder.local_part str
  in
  match result with
  | Ok local -> Ok (Colombe_emile.of_local local)
  | Error _ -> error_msgf "Invalid local-part (according RFC 5321): %S" str

module Key = struct
  include Colombe.Path

  let hash = Hashtbl.hash
end

module Value = struct
  type t = { to_expire: int }

  let weight _ = 1
end

module Cache = Lru.M.Make (Key) (Value)

type t = {
    name: Emile.local
  ; domain: Colombe.Domain.t
  ; counter: int
  ; subscribers: Colombe.Path.t list
  ; moderators: Colombe.Path.t list
  ; pending: Cache.t
}

let to_emile t =
  let domain = Colombe_emile.of_domain t.domain in
  { Emile.name= None; local= t.name; domain= (domain, []) }

type outgoing = {
    sender: Colombe.Reverse_path.t
  ; recipients: Colombe.Forward_path.t list
  ; seq: string Flux.stream Seq.t
}

let make ~domain name =
  {
    name
  ; domain
  ; counter= 0
  ; subscribers= []
  ; moderators= []
  ; pending= Cache.create 0x7ff
  }

let name t = local_to_string t.name
let domain t = t.domain

let messageID t =
  let now = Mirage_ptime.now () in
  let now = Ptime.to_float_s now in
  let now = Int64.of_float now in
  let seed = Mirage_crypto_rng.generate 16 in
  let uuid = Uuidm.v4 (Bytes.of_string seed) in
  let uuid = Uuidm.to_string uuid in
  let local = Fmt.str "%Ld.%s" now uuid in
  let str = Fmt.str "<%s@%s>" local (Colombe.Domain.to_string t.domain) in
  Mrmime.MessageID.of_string str |> Result.get_ok

let json ~name ~domain =
  let path =
    let dec str =
      match Colombe.Path.of_string (Fmt.str "<%s>" str) with
      | Ok v -> v
      | Error (`Msg msg) -> failwith msg
    in
    let enc { Colombe.Path.local; domain; _ } =
      Fmt.str "%s@%s"
        (Colombe.Path.Encoder.local_to_string local)
        (Colombe.Domain.to_string domain)
    in
    Jsont.map ~enc ~dec Jsont.string
  in
  let open Jsont.Object in
  map (fun counter subscribers moderators ->
      let pending = Cache.create 0x7ff in
      { name; domain; counter; subscribers; moderators; pending })
  |> mem "counter" ~enc:(fun t -> t.counter) Jsont.int
  |> mem "subscribers" ~enc:(fun t -> t.subscribers) (Jsont.list path)
  |> mem "moderators" ~enc:(fun t -> t.moderators) (Jsont.list path)
  |> finish

let p =
  let open Mrmime in
  let u = Field.(Witness Unstructured) in
  Field_name.Map.empty
  |> Field_name.Map.add Field_name.date u
  |> Field_name.Map.add Field_name.from u
  |> Field_name.Map.add Field_name.sender u
  |> Field_name.Map.add Field_name.reply_to u
  |> Field_name.Map.add (Field_name.v "To") u
  |> Field_name.Map.add Field_name.cc u
  |> Field_name.Map.add Field_name.bcc u
  |> Field_name.Map.add Field_name.subject u
  |> Field_name.Map.add Field_name.message_id u
  |> Field_name.Map.add Field_name.content_type u
  |> Field_name.Map.add Field_name.content_encoding u

let parse bstr =
  let open Mrmime in
  let len = Bstr.length bstr in
  let tmp = Bytes.create 0x7ff in
  let decoder = Hd.decoder p in
  let rec go fields pos = function
    | `Field field -> Hd.decode decoder |> go (Location.prj field :: fields) pos
    | `End prelude ->
        let hdrl = pos - String.length prelude in
        let bodyl = Int.max 0 (len - hdrl) in
        let body = Bstr.sub bstr ~off:hdrl ~len:bodyl in
        let hdr = Header.of_list (List.rev fields) in
        Ok (hdr, body)
    | `Malformed _ -> error_msgf "Invalid email"
    | `Await when pos >= len ->
        Hd.src decoder String.empty 0 0;
        Hd.decode decoder |> go fields pos
    | `Await ->
        let available = Int.min (Bytes.length tmp) (len - pos) in
        Bstr.blit_to_bytes bstr ~src_off:pos tmp ~dst_off:0 ~len:available;
        Hd.src decoder (Bytes.unsafe_to_string tmp) 0 available;
        Hd.decode decoder |> go fields (pos + available)
  in
  go [] 0 `Await

let make_new_from t ~from =
  let open Mrmime.Mailbox in
  let name =
    Fmt.str "%a via %a" Colombe.Reverse_path.pp from Emile.pp_local t.name
  in
  let name = Phrase.(v [ e ~encoding:q name ]) in
  let domain = Colombe_emile.of_domain t.domain in
  make ~name t.name domain

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

let to_unstrctrd unstructured =
  let fold acc = function #Unstrctrd.elt as elt -> elt :: acc | _ -> acc in
  let unstrctrd = List.fold_left fold [] unstructured in
  Result.get_ok (Unstrctrd.of_list (List.rev unstrctrd))

let rewrite t ~from bstr =
  let open Mrmime in
  let* hdrs, body = parse bstr in
  let hdrs = Header.remove_assoc Field_name.from hdrs in
  let hdrs = Header.remove_assoc Field_name.message_id hdrs in
  let from' = make_new_from t ~from in
  let hdrs = Header.add Field_name.from (Field.Mailboxes, [ from' ]) hdrs in
  let hdrs =
    if Header.exists Field_name.reply_to hdrs then hdrs
    else
      match Colombe_emile.of_reverse_path from with
      | None -> hdrs
      | Some m ->
          let v = (Field.Addresses, [ Address.mailbox m ]) in
          Header.add Field_name.reply_to v hdrs
  in
  let listID =
    (* NOTE(dinosaure): [Colombe_emile.to_local] ensures that [t.name] is valid
       through RFC 5321. Then, we encode it with what Colombe can give to us
       (and use through the SMTP protocol). *)
    let local = Colombe_emile.to_local t.name in
    let local = Colombe.Path.Encoder.local_to_string local in
    let str = Fmt.str "<%s.%a>\r\n" local Colombe.Domain.pp t.domain in
    let v = Unstrctrd.of_string str |> Result.get_ok |> snd in
    (Field.Unstructured, (v :> Unstructured.t))
  in
  let messageID = messageID t in
  let listPost = Mailto.make [ to_emile t ] in
  let listPost = Mailto.to_unstrctrd listPost in
  let listPost = Mrmime.Field.(Unstructured, (listPost :> Unstructured.t)) in
  let sender = Mrmime.Field.(Mailbox, to_emile t) in
  let hdrs = Header.add (Field_name.v "List-Id") listID hdrs in
  let hdrs = Header.add (Field_name.v "Sender") sender hdrs in
  let hdrs = Header.add (Field_name.v "List-Post") listPost hdrs in
  let hdrs =
    Header.add
      (Field_name.v "Message-Id")
      (Mrmime.Field.MessageID, messageID)
      hdrs
  in
  (* NOTE(dinosaure): we return a process which reconstruct our email /forever/.
     By this way, we avoid the copy of the body. *)
  let seq =
    Seq.forever @@ fun () ->
    let hdrs =
      (* NOTE(dinosaure): it's really important to not set [margin] and keep
         unstructured values as they are (without breaking if they exceed a
         margin, like 998 bytes). *)
      Prettym.to_stream ~margin:None ~new_line:"\r\n" Header.Encoder.header hdrs
    in
    let hdrs = Seq.of_dispenser hdrs in
    let hdrs = Seq.append hdrs (Seq.singleton "\r\n") in
    let src = Flux.Source.seq hdrs in
    let s0 = Flux.Stream.from src in
    let s1 = Flux.Stream.from (from_bstr body) in
    Flux.Stream.concat s0 s1
  in
  Ok seq

let is_loop t bstr =
  let open Mrmime in
  let* hdrs, _ = parse bstr in
  let our_listID =
    let local = Colombe_emile.to_local t.name in
    let local = Colombe.Path.Encoder.local_to_string local in
    Fmt.str "<%s.%a>" local Colombe.Domain.pp t.domain
  in
  let fields = Header.assoc (Field_name.v "List-Id") hdrs in
  let fn = function
    | Field.Field (_, Unstructured, v) ->
        let default = to_unstrctrd v in
        let v = Unstrctrd.without_comments default in
        let v = Result.value ~default v in
        let v = Unstrctrd.fold_fws v in
        let v = Unstrctrd.to_utf_8_string v in
        let v = String.trim v in
        Some v
    | _ -> None
  in
  let fields = List.filter_map fn fields in
  let fn str = String.equal str our_listID in
  Ok (List.exists fn fields)

(* Variable Envelope Return Path *)
let encode_verp { Colombe.Path.local; domain; _ } =
  let open Colombe in
  Fmt.str "%s=%s" (Path.Encoder.local_to_string local) (Domain.to_string domain)

let forward t ~from bstr =
  let* seq = rewrite t ~from bstr in
  let fn subscriber =
    let verp = encode_verp subscriber in
    let local = Colombe_emile.to_local t.name in
    let local = Colombe.Path.Encoder.local_to_string local in
    let local = Fmt.str "%s-return-%d-%s" local t.counter verp in
    let local = String.split_on_char '.' local in
    let local = `Dot_string local in
    let sender = { Colombe.Path.local; domain= t.domain; rest= [] } in
    let recipients = [ Colombe.Forward_path.Forward_path subscriber ] in
    { sender= Some sender; recipients; seq }
  in
  let ms = List.map fn t.subscribers in
  Ok ({ t with counter= t.counter + 1 }, ms, [])

let forward t ~from bstr =
  let* is_loop = is_loop t bstr in
  if is_loop then Ok (t, [], []) else forward t ~from bstr

let subscribe t ~from =
  let already_subscriber =
    match from with
    | None -> true
    | Some path -> List.exists (Colombe.Path.equal path) t.subscribers
  in
  if already_subscriber then Ok (t, [], [])
  else
    let open Mrmime in
    let sender = Field.Field (Field_name.sender, Mailbox, to_emile t) in
    let subject =
      let open Unstructured.Craft in
      let value = compile [ v "New subscription" ] in
      Field.Field (Field_name.subject, Unstructured, value)
    in
    let date =
      let now = Mirage_ptime.now () in
      let now = Date.of_ptime ~zone:Date.Zone.GMT now in
      Field.Field (Field_name.date, Date, now)
    in
    let mime_version =
      let open Unstructured.Craft in
      let value = compile [ v "1.0" ] in
      Field.Field (Field_name.mime_version, Unstructured, value)
    in
    let content_type =
      let open Content_type in
      let params = Parameters.of_list [ ("charset", `Token "utf-8") ] in
      let v = make `Text (`Iana_token "plain") params in
      Field.Field (Field_name.content_type, Content, v)
    in
    let to_ =
      let fn m = `Mailbox (Colombe_emile.of_path m) in
      let addresses = List.map fn t.moderators in
      Field.Field (Field_name.v "To", Addresses, addresses)
    in
    let messageID =
      Field.Field (Field_name.message_id, MessageID, messageID t)
    in
    let hdrs =
      let from = Field.Field (Field_name.from, Mailboxes, [ to_emile t ]) in
      Header.of_list
        [
          messageID; mime_version; date; subject; from; sender; content_type
        ; to_
        ]
    in
    let to_accept =
      let from = Option.get from in
      let local = Fmt.str "subscribe-accept-%s" (encode_verp from) in
      let local = String.split_on_char '.' local in
      let local = `Dot_string local in
      let path = { Colombe.Path.local; domain= t.domain; rest= [] } in
      Colombe.Forward_path.Forward_path path
    in
    let to_reject =
      let from = Option.get from in
      let local = Fmt.str "subscribe-reject-%s" (encode_verp from) in
      let local = String.split_on_char '.' local in
      let local = `Dot_string local in
      let path = { Colombe.Path.local; domain= t.domain; rest= [] } in
      Colombe.Forward_path.Forward_path path
    in
    let body =
      Fmt.str
        "A new person %s would like to subscribe to our mailing list %s.\r\n\
         You can accept this person by sending an email to %s or reject \r\n\
         this person by sending an email to %s.\r\n"
        (Colombe.Reverse_path.Encoder.to_string from)
        (Emile.to_string (to_emile t))
        (Colombe.Forward_path.Encoder.to_string to_accept)
        (Colombe.Forward_path.Encoder.to_string to_reject)
    in
    let seq =
      Seq.forever @@ fun () ->
      let consumed = ref false in
      let body () =
        if !consumed then None
        else begin
          consumed := true;
          let len = String.length body in
          Some (body, 0, len)
        end
      in
      let m = Mt.make hdrs Mt.simple (Mt.part body) in
      let dispenser = Mt.to_stream m in
      let seq = Seq.of_dispenser dispenser in
      let seq = Seq.map (fun (str, off, len) -> String.sub str off len) seq in
      Flux.Source.seq seq |> Flux.Stream.from
    in
    let fn moderator =
      let sender = to_emile t in
      let sender = Colombe_emile.to_path sender in
      let recipients = [ Colombe.Forward_path.Forward_path moderator ] in
      { sender= Some sender; recipients; seq }
    in
    let ms = List.map fn t.moderators in
    Ok (t, [], ms)

(*
let bounce t rcpt =
  match String.index_opt rcpt '-' with
  | None ->
      Log.warn (fun m -> m "Invalid VERP bounce: %s" rcpt);
      (t, [])
  | Some i -> (
      let counter_str = String.sub rcpt 0 i in
      let encoded = String.sub rcpt (i + 1) (String.length rcpt - i - 1) in
      match int_of_string_opt counter_str with
      | None ->
          Log.warn (fun m -> m "Invalid bounce counter: %s" counter_str);
          (t, [])
      | Some counter -> (
          let email_str =
            String.concat "@" (String.split_on_char '=' encoded)
          in
          match path_of_string email_str with
          | None ->
              Log.warn (fun m -> m "Invalid VERP email: %s" email_str);
              (t, [])
          | Some path ->
              if not (path_mem path t.subscribers) then (t, [])
              else
                let prev =
                  List.find_opt (fun (_, _, e) -> e = path) t.bounces
                in
                let prev_counter, prev_score =
                  match prev with Some (c, s, _) -> (c, s) | None -> (-1, 0)
                in
                let score =
                  if prev_counter = -1 || prev_counter = counter - 1 then
                    prev_score + 1
                  else 1
                in
                let bounces_clean =
                  List.filter (fun (_, _, e) -> not (e = path)) t.bounces
                in
                if score >= 5 then begin
                  Log.info (fun m ->
                      m "Removing %s from %s (too many bounces)"
                        (path_to_string path) t.name);
                  let subscribers =
                    List.filter (fun p -> not (p = path)) t.subscribers
                  in
                  ({ t with subscribers; bounces= bounces_clean }, [])
                end
                else
                  ( { t with bounces= (counter, score, path) :: bounces_clean }
                  , [] )))
*)

let match_mailing_list t parts =
  let name =
    let local = Colombe_emile.to_local t.name in
    let local = Colombe.Path.Encoder.local_to_string local in
    String.split_on_char '-' local
  in
  let rec go name' parts' =
    match (name', parts') with
    | [], rest -> Ok rest
    | x :: name', y :: parts' when String.equal x y -> go name' parts'
    | _ ->
        error_msgf
          "The receiver %s does not match the name of the mailing-list %a"
          (String.concat "-" parts) Emile.pp_local t.name
  in
  go name parts

type error = [ `Msg of string ]

let incoming t ~from ~rcpt:{ Colombe.Path.local; _ } bstr =
  let local = Colombe.Path.Encoder.local_to_string local in
  let parts = String.split_on_char '-' local in
  let* rem = match_mailing_list t parts in
  begin match rem with
  | [] -> forward t ~from bstr
  | [ "subscribe" ] -> subscribe t ~from
  (*
  | [ "subscribe" ] -> subscribe t from
  | "subscribe" :: "reject" :: rem -> reject t from (String.concat "-" rem)
  | "subscribe" :: "accept" :: rem | "subscribe" :: rem ->
      confirmation t from (String.concat "-" rem)
  | "return" :: rem -> bounce t (String.concat "-" rem)
  | "moderate" :: "accept" :: rem -> accept t from (String.concat "-" rem)
  | "moderate" :: "reject" :: rem -> disallow t flow (String.concat "-" rem)
  *)
  | _ -> Ok (t, [], [])
  end
