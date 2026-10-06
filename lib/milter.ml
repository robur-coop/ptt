let src = Logs.Src.create "ptt.milter"
let ( let@ ) finally fn = Fun.protect ~finally fn

module Log = (val Logs.src_log src : Logs.LOG)

type info = Ptt.info
type email = Ptt.email
type ic = email Miou.Computation.t

type decision =
  [ `Continue | `Accept | `Reject | `Tempfail | `Add_header of string * string ]

type oc = decision Miou.Computation.t
type error = [ `Closed | `Protocol of string ]

let pp_error ppf = function
  | `Closed -> Fmt.string ppf "Connection closed by peer"
  | `Protocol msg -> Fmt.pf ppf "Protocol error: %s" msg

(* NOTE(dinosaure): the milter connection is reset by [nec] for every accepted
   [flow] (one message per connection, like the SMTP relay handler). We raise
   this when the connection is interrupted before the end-of-body so that the
   signing fiber awaiting [ic] is released. *)
exception Aborted

let aborted =
  let bt = Printexc.get_callstack 0 in
  (Aborted, bt)

let smfif_addhdrs = 0x01l (* we would like to add a header. *)

(*            0x01 |         0x02 |         0x04 |         0x08: 0x0F
   SMFIP_NOCONNECT | SMFIP_NOHELO | SMFIP_NOMAIL | SMFIP_NORCPT: a DKIM signer
   only needs the headers and the body, so we ask the MTA to skip the envelope
   stages entirely. *)
let skip_flags = 0x0Fl
let max_packet = 0x1000000 (* 16MiB sanity cap. *)

module Wire = struct
  (* uint32 len         Size of data to follow
     char   cmd         Command/response code
     char   data[len-1] Code-specific data (may be empty)
   *)
  let packet cmd data =
    let len = 1 + String.length data in
    let buf = Bytes.create (4 + len) in
    Bytes.set_int32_be buf 0 (Int32.of_int len);
    Bytes.set buf 4 cmd;
    Bytes.blit_string data 0 buf 5 (String.length data);
    Bytes.unsafe_to_string buf

  let cstring str off =
    match String.index_from_opt str off '\000' with
    | Some idx -> (String.sub str off (idx - off), idx + 1)
    | None -> (String.sub str off (String.length str - off), String.length str)

  let get_int32 data off =
    if String.length data >= off + 4 then String.get_int32_be data off else 0l

  let optneg_response data =
    let mta_version =
      if String.length data >= 4 then get_int32 data 0 else 2l
    in
    let mta_protocol = get_int32 data 8 in
    let version =
      let v = if Int32.compare mta_version 6l > 0 then 6l else mta_version in
      if Int32.compare v 2l < 0 then 2l else v
    in
    (* Only ask to skip what the MTA advertises it can skip. *)
    let protocol = Int32.logand skip_flags mta_protocol in
    let buf = Bytes.create 12 in
    Bytes.set_int32_be buf 0 version;
    Bytes.set_int32_be buf 4 smfif_addhdrs;
    Bytes.set_int32_be buf 8 protocol;
    Bytes.unsafe_to_string buf

  let add_header ~name ~value =
    packet 'h' (String.concat "" [ name; "\000"; value; "\000" ])
end

let read_exactly flow n =
  if n = 0 then ""
  else begin
    let buf = Bytes.create n in
    Mnet.TCP.really_input flow buf ~off:0 ~len:n;
    Bytes.unsafe_to_string buf
  end

let read_packet flow =
  let hdr = read_exactly flow 4 in
  let len = Int32.to_int (String.get_int32_be hdr 0) in
  if len < 1 || len > max_packet then
    Fmt.failwith "Invalid milter packet length: %d" len;
  let cmd = (read_exactly flow 1).[0] in
  let data = read_exactly flow (len - 1) in
  (cmd, data)

let write flow cmd data = Mnet.TCP.write flow (Wire.packet cmd data)
let continue flow = write flow 'c' ""

let handler ?encoder:_ ?decoder:_ ?queue:_ ~info flow (ic, oc) q =
  let flow = Mnet.TCP.unsafe_to_bufferize ~limit:None 0x100 flow in
  let _, (peer, port) = Mnet.TCP.peers flow in
  Log.debug (fun m -> m "New milter client: %a:%d" Ipaddr.pp peer port);
  let ic_done = ref false in
  (* true: when we send back the email to the caller. *)
  let finished = ref false in
  (* true: when the client sent to us 'E' (End of body marker).
     Then, we should send modification. *)
  let ensure_ic () =
    if not !ic_done then begin
      ic_done := true;
      let from = (None, [])
      and recipients = []
      and domain_from = info.Ptt.domain in
      let email = { Ptt.from; recipients; domain_from } in
      ignore (Miou.Computation.try_return ic email)
    end
  in
  let put str = if not (Flux.Bqueue.closed q) then Flux.Bqueue.put q str in
  let cleanup () =
    if not !finished then begin
      if not (Flux.Bqueue.closed q) then Flux.Bqueue.close q;
      ignore (Miou.Computation.try_cancel ic aborted)
    end
  in
  (* End-of-body: the signing fiber has been consuming [q]; close it so the
     signer terminates, then emit its decision back to the MTA. *)
  let end_of_body () =
    finished := true;
    ensure_ic ();
    if not (Flux.Bqueue.closed q) then Flux.Bqueue.close q;
    match Miou.Computation.await_exn oc with
    | `Add_header (name, value) ->
        Log.debug (fun m -> m "Add header %s to %a:%d" name Ipaddr.pp peer port);
        Mnet.TCP.write flow (Wire.add_header ~name ~value);
        continue flow;
        Ok ()
    | `Continue | `Accept -> continue flow; Ok ()
    | `Reject -> write flow 'r' ""; Ok ()
    | `Tempfail -> write flow 't' ""; Ok ()
  in
  let rec go () =
    match read_packet flow with
    | exception End_of_file -> Ok ()
    | exception Mnet.TCP.Closed_by_peer -> Ok ()
    | exception Failure msg -> Error (`Protocol msg)
    | cmd, data ->
        begin match cmd with
        | 'O' ->
            Mnet.TCP.write flow (Wire.packet 'O' (Wire.optneg_response data));
            go ()
        | 'D' -> go () (* macros: no response expected. *)
        | 'L' ->
            let name, off = Wire.cstring data 0 in
            let value, _ = Wire.cstring data off in
            ensure_ic ();
            put (String.concat "" [ name; ": "; value; "\r\n" ]);
            continue flow;
            go ()
        | 'N' -> ensure_ic (); put "\r\n"; continue flow; go ()
        | 'B' -> ensure_ic (); put data; continue flow; go ()
        | 'E' -> end_of_body ()
        | 'A' -> Ok () (* abort: drop the current message. *)
        | 'Q' -> Ok ()
        (* connect/helo/mail/rcpt/data/unknown: acknowledge and ignore. *)
        | _ -> continue flow; go ()
        end
  in
  let@ () = cleanup in
  go ()
