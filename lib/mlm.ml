let msgf fmt = Fmt.kstr (fun msg -> `Msg msg) fmt
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt
let ( let* ) = Result.bind
let src = Logs.Src.create "mlm"

module Log = (val Logs.src_log src : Logs.LOG)

let local_to_string local =
  let local = Colombe_emile.to_local local in
  Colombe.Path.Encoder.local_to_string local

let local_of_string str =
  let result =
    Angstrom.parse_string ~consume:All Colombe.Path.Decoder.local_part str
  in
  match result with
  | Ok local -> Ok local
  | Error _ -> error_msgf "Invalid local-part (according RFC 5321): %S" str

module Pending_subscriptions = struct
  module Key = struct
    include Colombe.Path

    let hash = Hashtbl.hash
  end

  module Value = struct
    type t = { expire_at: Ptime.t }

    let weight _ = 1
  end

  include Lru.M.Make (Key) (Value)
end

(* bounces/undeliverable mails
  - connection to remote MX failed / MX complained about mailbox full or user does not exist
    --> add the failing subscriber to our list of failures
  - successfully delivered the mail, and the remote MX forwards it to some other mail server
    -> that can now as well fail, but our connection is already closed
    -> the MX that failed to forward it, will send back an automated reply to ptt-bounce-12-reyn.or=data.coop@mailingl.st

  what to do with failures?
    usually, we accept up to 3 failures in a row.
    if mail 1 couldn't be delivered by any means to hannes@mehnert.org, that's fine. but we remember that.
    if mail 2 ..
    if mail 3 as well failed to deliver, we unsubscribe hannes@mehnert.org

    if mail 2 actually succeeds (or mail 3), we remove all hannes@mehnert.org from the list of bounces


  simply unsubscribe if there's a failure <- that's the alternative, much easier

  we send an email to reynir@data.coop with ptt-14-reynir=data@coop@mailingl.st
  -> we fail
  -> we add reynir@data.coop, failed: 14 into our bounces list
  -> we receive an email with RCPT-TO:<ptt-return-14-reynir=data.coop@mailingl.st
  -> we add reynir@data.coop with attempts +  1 to our bounces

  -> our bounce list grows with our failures when we would like to send emails
     + also grows when we receive email such as ptt-return-*-forward-path@mailingl.st

     --> whenever the bounce list grows, we check whether it is now above 5
        -> then we unsubscribe, and empty the bounce list for that subscriber

      --> whenever we successfully deliver a mail, we empty the bounce list

 *)
type t = {
    name: Emile.local
  ; domain: Colombe.Domain.t
  ; counter: int
  ; subscribers: Colombe.Path.t list
  ; moderators: Colombe.Path.t list
  ; pending: Pending_subscriptions.t
  ; bounces: (Colombe.Path.t, int list) Hashtbl.t
  ; store: t -> unit
}

let to_emile t =
  let domain = Colombe_emile.of_domain t.domain in
  { Emile.name= None; local= t.name; domain= (domain, []) }

(* Variable Envelope Return Path

   NOTE(dinosaure): RFC5322 accepts '=' into the domain-part but RFC5321 disallows it.
   so it safe to use '=' as a separator instead of '@' and reconstruct, at least, the
   right part (the domain) safely. *)
let encode_verp { Colombe.Path.local; domain; _ } =
  let open Colombe in
  Fmt.str "%s=%s" (Path.Encoder.local_to_string local) (Domain.to_string domain)

let decode_verp str =
  match List.rev (String.split_on_char '=' str) with
  | domain :: rlocal ->
      let local = List.rev rlocal in
      let local = String.concat "=" local in
      let* domain = Colombe.Domain.of_string domain in
      let* local = local_of_string local in
      Ok { Colombe.Path.local; domain; rest= [] }
  | _ -> assert false
(* NOTE(dinosaure): impossible case, [String.split_on_char] returns always a non-empty list. *)

type outgoing = {
    sender: Colombe.Reverse_path.t
  ; recipients: Colombe.Forward_path.t list
  ; seq: string Flux.stream Seq.t
}

type tx = { sender: Colombe.Reverse_path.t; recipient: Colombe.Forward_path.t }

let make ~domain name =
  {
    name
  ; domain
  ; counter= 0
  ; subscribers= []
  ; moderators= []
  ; pending= Pending_subscriptions.create 0x7ff
  ; bounces= Hashtbl.create 0x7ff
  ; store= ignore
  }

let name t = local_to_string t.name
let domain t = t.domain

let is_moderator ~from t =
  match from with
  | None -> false
  | Some path ->
      let fn = Colombe.Path.equal path in
      List.exists fn t.moderators

let is_subscriber t path =
  let fn = Colombe.Path.equal path in
  List.exists fn t.subscribers

let messageID ?g t =
  let now = Mirage_ptime.now () in
  let now = Ptime.to_float_s now in
  let now = Int64.of_float now in
  let seed = Mirage_crypto_rng.generate ?g 16 in
  let uuid = Uuidm.v4 (Bytes.of_string seed) in
  let uuid = Uuidm.to_string uuid in
  let local = Fmt.str "%Ld.%s" now uuid in
  let str = Fmt.str "<%s@%s>" local (Colombe.Domain.to_string t.domain) in
  Mrmime.MessageID.of_string str |> Result.get_ok

let json ?(store = ignore) ~domain name =
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
      let pending = Pending_subscriptions.create 0x7ff in
      let bounces (* TODO *) = Hashtbl.create 0x7ff in
      {
        name
      ; domain
      ; counter
      ; subscribers
      ; moderators
      ; pending
      ; bounces
      ; store
      })
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
    match from with
    | None -> None
    | Some path ->
        let verp = encode_verp path in
        let str = Fmt.str "%s via %a" verp Emile.pp_local t.name in
        Some Phrase.(v [ e ~encoding:q str ])
  in
  let domain = Colombe_emile.of_domain t.domain in
  make ?name t.name domain

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
  let* hdrs, (body : Bstr.t) = parse bstr in
  let hdrs = Header.remove_assoc Field_name.from hdrs in
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
  let listPost = Mailto.make [ to_emile t ] in
  let listPost = Mailto.to_unstrctrd listPost in
  let listPost = Mrmime.Field.(Unstructured, (listPost :> Unstructured.t)) in
  (* Sender required by Outlook. *)
  let sender = Mrmime.Field.(Mailbox, to_emile t) in
  let hdrs = Header.add (Field_name.v "List-Id") listID hdrs in
  let hdrs = Header.add (Field_name.v "Sender") sender hdrs in
  let hdrs = Header.add (Field_name.v "List-Post") listPost hdrs in
  let hdrs =
    (* NOTE(dinosaure): add Message-ID iff it does not exist. *)
    if Header.exists Field_name.message_id hdrs then hdrs
    else
      let messageID = messageID t in
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

let rewrite_and_forward t ~from recipients bstr =
  let* seq = rewrite t ~from bstr in
  Ok (t, [ { sender= from; recipients; seq } ], [])

let forward_incoming t ~from recipients bstr =
  let* is_loop = is_loop t bstr in
  let is_subscriber =
    let some = is_subscriber t in
    Option.fold ~none:false ~some from
  in
  if (not is_loop) && is_subscriber then
    rewrite_and_forward t ~from recipients bstr
  else Ok (t, [], [])

let forward_outgoing t =
  let fn subscriber =
    let verp = encode_verp subscriber in
    let local = Colombe_emile.to_local t.name in
    let local = Colombe.Path.Encoder.local_to_string local in
    let local = Fmt.str "%s-return-%d-%s" local t.counter verp in
    let local = String.split_on_char '.' local in
    let local = `Dot_string local in
    let sender = { Colombe.Path.local; domain= t.domain; rest= [] } in
    let recipient = Colombe.Forward_path.Forward_path subscriber in
    { sender= Some sender; recipient }
  in
  let ms = List.map fn t.subscribers in
  let t = { t with counter= t.counter + 1 } in
  t.store t;
  Ok (t, ms)

let _10d = Ptime.Span.of_int_s 864000

let subscribe t ~from =
  let already_subscriber =
    let some = is_subscriber t in
    Option.fold ~none:true ~some from
  in
  let already_pending =
    let some p = Pending_subscriptions.mem p t.pending in
    Option.fold ~none:true ~some from
  in
  if already_subscriber || already_pending then Ok (t, [], [])
  else
    let open Mrmime in
    (* NOTE(dinosaure): let's craft a new email! *)
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
      let local =
        Fmt.str "%s-subscribe-accept-%s" (local_to_string t.name)
          (encode_verp from)
      in
      let local = String.split_on_char '.' local in
      let local = `Dot_string local in
      let path = { Colombe.Path.local; domain= t.domain; rest= [] } in
      Colombe.Forward_path.Forward_path path
    in
    let to_reject =
      let from = Option.get from in
      let local =
        Fmt.str "%s-subscribe-reject-%s" (local_to_string t.name)
          (encode_verp from)
      in
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
    let fn from =
      let now = Mirage_ptime.now () in
      let expire_at = Ptime.add_span now _10d in
      let expire_at = Option.get expire_at in
      (* NOTE(dinosaure): [Option.get] should be safe. *)
      Pending_subscriptions.add from { expire_at } t.pending;
      Pending_subscriptions.trim t.pending
    in
    Option.iter fn from;
    Ok (t, [], ms)

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

let rec clean_up t =
  let than = Mirage_ptime.now () in
  match Pending_subscriptions.lru t.pending with
  | Some (k, { expire_at }) when Ptime.is_earlier expire_at ~than ->
      Log.debug (fun m ->
          m "Remove %a from pending subscription, (too old)" Colombe.Path.pp k);
      Pending_subscriptions.remove k t.pending;
      clean_up t
  | _ -> ()

let failure_for t ~from forward_path =
  let counter = function
    | _name :: "return" :: counter :: _ ->
        let none = msgf "Invalid counter" in
        Option.to_result ~none (int_of_string_opt counter)
    | _ -> error_msgf "Invalid return-path email address"
  in
  match from with
  | None -> Ok ()
  | Some { Colombe.Path.local; _ } ->
      let local = Colombe.Path.Encoder.local_to_string local in
      let parts = String.split_on_char '-' local in
      let* counter = counter parts in
      begin match Hashtbl.find_opt t.bounces forward_path with
      | Some attempts when List.length attempts < 3 ->
          let attempts = List.sort_uniq Int.compare (counter :: attempts) in
          Hashtbl.replace t.bounces forward_path attempts;
          Ok ()
      | Some _ ->
          Log.debug (fun m ->
              m "Too many failures for %a, remove it as a subscriber for %a"
                Colombe.Path.pp forward_path Emile.pp_mailbox (to_emile t));
          Ok ()
      | None ->
          Hashtbl.add t.bounces forward_path [ counter ];
          Ok ()
      end

let outgoing t ~from ~rcpt:{ Colombe.Path.local; _ } =
  clean_up t;
  let local = Colombe.Path.Encoder.local_to_string local in
  let parts = String.split_on_char '-' local in
  let* rem = match_mailing_list t parts in
  begin match rem with
  | [] -> forward_outgoing t
  | _ ->
      Log.warn (fun m ->
          m "Ignoring email from %a" Colombe.Reverse_path.pp from);
      Ok (t, [])
  end

let incoming t ~from ~rcpt:({ Colombe.Path.local; _ } as rcpt) bstr =
  clean_up t;
  let local = Colombe.Path.Encoder.local_to_string local in
  let parts = String.split_on_char '-' local in
  let* rem = match_mailing_list t parts in
  begin match rem with
  | [] -> forward_incoming t ~from [ Forward_path rcpt ] bstr
  | [ "subscribe" ] -> subscribe t ~from
  | "subscribe" :: "accept" :: rem ->
      let verp = String.concat "-" rem in
      let* new_subscriber = decode_verp verp in
      if is_moderator ~from t then begin
        Pending_subscriptions.remove new_subscriber t.pending;
        Log.debug (fun m ->
            m "New subscriber for %a: %a" Emile.pp_mailbox (to_emile t)
              Colombe.Path.pp new_subscriber);
        let t = { t with subscribers= new_subscriber :: t.subscribers } in
        t.store t;
        Ok (t, [], [])
      end
      else
        error_msgf "%a is not authorized as a moderator for %a"
          Colombe.Reverse_path.pp from Emile.pp_mailbox (to_emile t)
  | "subscribe" :: "reject" :: rem ->
      let verp = String.concat "-" rem in
      let* new_subscriber = decode_verp verp in
      if is_moderator ~from t then begin
        Pending_subscriptions.remove new_subscriber t.pending;
        Ok (t, [], [])
      end
      else
        error_msgf "%a is not authorized as a moderator for %a"
          Colombe.Reverse_path.pp from Emile.pp_mailbox (to_emile t)
  | "return" :: counter :: rem ->
      let verp = String.concat "-" rem in
      let* forward_path = decode_verp verp in
      let* counter =
        let none = msgf "Invalid counter" in
        Option.to_result ~none (int_of_string_opt counter)
      in
      if is_subscriber t forward_path then begin
        Log.debug (fun m ->
            m "Received a failure for %a" Colombe.Path.pp forward_path);
        begin match Hashtbl.find_opt t.bounces forward_path with
        | Some attempts when List.length attempts < 3 ->
            let attempts = List.sort_uniq Int.compare (counter :: attempts) in
            Hashtbl.replace t.bounces forward_path attempts
        | Some _ ->
            Log.debug (fun m ->
                m "Too many failures for %a, remove it as a subscriber for %a"
                  Colombe.Path.pp forward_path Emile.pp_mailbox (to_emile t))
        | None -> Hashtbl.add t.bounces forward_path [ counter ]
        end;
        Ok (t, [], [])
      end
      else Ok (t, [], [])
  | _ ->
      Log.warn (fun m ->
          m "Ignoring email from %a" Colombe.Reverse_path.pp from);
      Ok (t, [], [])
  end
