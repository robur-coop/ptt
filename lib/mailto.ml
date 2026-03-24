type t = { to_: Emile.mailbox list; headers: (string * string) list }

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let make ?(headers = []) to_ =
  let fn { Emile.local; domain= domain, _; _ } =
    { Emile.name= None; local; domain= (domain, []) }
  in
  let to_ = List.map fn to_ in
  { to_; headers }

let to_ t = t.to_
let headers t = t.headers

let subject t =
  let rec go = function
    | [] -> None
    | (name, value) :: _ when String.lowercase_ascii name = "subject" ->
        Some value
    | _ :: rest -> go rest
  in
  go t.headers

let body t =
  let rec go = function
    | [] -> None
    | (name, value) :: _ when String.lowercase_ascii name = "body" -> Some value
    | _ :: rest -> go rest
  in
  go t.headers

let is_unreserved = function
  | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' -> true
  | '-' | '_' | '.' | '!' | '~' | '*' | '\'' | '(' | ')' -> true
  | _ -> false

let hex_digit n =
  if n < 10 then Char.chr (n + Char.code '0')
  else Char.chr (n - 10 + Char.code 'A')

let percent_encode str =
  let buf = Buffer.create (String.length str) in
  let fn chr =
    if is_unreserved chr then Buffer.add_char buf chr
    else begin
      let byte = Char.code chr in
      Buffer.add_char buf '%';
      Buffer.add_char buf (hex_digit (byte lsr 4));
      Buffer.add_char buf (hex_digit (byte land 0xf))
    end
  in
  String.iter fn str; Buffer.contents buf

let hex_value chr =
  match chr with
  | '0' .. '9' -> Some (Char.code chr - Char.code '0')
  | 'A' .. 'F' -> Some (Char.code chr - Char.code 'A' + 10)
  | 'a' .. 'f' -> Some (Char.code chr - Char.code 'a' + 10)
  | _ -> None

let percent_decode str =
  let len = String.length str in
  let buf = Buffer.create len in
  let rec go idx =
    if idx >= len then Ok (Buffer.contents buf)
    else if str.[idx] = '%' then
      begin if idx + 2 >= len then error_msgf "Truncated percent-encoding"
      else
        match (hex_value str.[idx + 1], hex_value str.[idx + 2]) with
        | Some hi, Some lo ->
            Buffer.add_char buf (Char.chr ((hi lsl 4) lor lo));
            go (idx + 3)
        | _ -> error_msgf "Invalid percent-encoding"
      end
    else begin
      Buffer.add_char buf str.[idx];
      go (idx + 1)
    end
  in
  go 0

let mailbox_decode str =
  match Emile.of_string str with
  | Ok { Emile.name= None; domain= _, []; _ } as value -> value
  | Ok m -> error_msgf "Invalid mailbox: %a" Emile.pp_mailbox m
  | Error _ -> error_msgf "Invalid mailbox: %S" str

let split_on_first chr str =
  match String.index_opt str chr with
  | None -> None
  | Some idx ->
      let len = String.length str in
      let s0 = String.sub str 0 idx in
      let s1 = String.sub str (idx + 1) (len - idx - 1) in
      Some (s0, s1)

let split_on_char_nonempty c s =
  let parts = String.split_on_char c s in
  List.filter (fun s -> String.length s > 0) parts

let ( let* ) = Result.bind

let unfold str =
  let len = String.length str in
  if len >= 2 && str.[0] = '<' && str.[len - 1] = '>' then
    Ok (String.sub str 1 (len - 2))
  else error_msgf "Given string is not surrounded: %S" str

let of_string str =
  let str = String.trim str in
  let* str = unfold str in
  let* scheme, rest =
    match split_on_first ':' str with
    | Some (scheme, rest) -> Ok (scheme, rest)
    | None -> error_msgf "Missing ':' in mailto URI"
  in
  if String.lowercase_ascii scheme <> "mailto" then
    error_msgf "Expected 'mailto' scheme, got %S" scheme
  else
    let addr_part, header_part =
      match split_on_first '?' rest with
      | Some (a, h) -> (a, Some h)
      | None -> (rest, None)
    in
    let* to_ =
      if String.length addr_part = 0 then Ok []
      else
        let raw_addrs = split_on_char_nonempty ',' addr_part in
        let rec go acc = function
          | [] -> Ok (List.rev acc)
          | raw :: rest ->
              let* decoded = mailbox_decode raw in
              go (decoded :: acc) rest
        in
        go [] raw_addrs
    in
    let* headers =
      match header_part with
      | None -> Ok []
      | Some h ->
          let raw_headers = split_on_char_nonempty '&' h in
          let rec go acc = function
            | [] -> Ok (List.rev acc)
            | raw :: rest ->
                begin match split_on_first '=' raw with
                | None -> error_msgf "Malformed header: %S" raw
                | Some (n, v) ->
                    let* name = percent_decode n in
                    let* value = percent_decode v in
                    go ((name, value) :: acc) rest
                end
          in
          go [] raw_headers
    in
    Ok { to_; headers }

let to_string t =
  let buf = Buffer.create 64 in
  Buffer.add_string buf "<mailto:";
  let rec add_addrs = function
    | [] -> ()
    | [ addr ] ->
        let str = Emile.to_string addr in
        Buffer.add_string buf str
    | addr :: rest ->
        let str = Emile.to_string addr in
        Buffer.add_string buf str; Buffer.add_char buf ','; add_addrs rest
  in
  add_addrs t.to_;
  begin match t.headers with
  | [] -> ()
  | headers ->
      Buffer.add_char buf '?';
      let rec add_headers = function
        | [] -> ()
        | [ (name, value) ] ->
            Buffer.add_string buf (percent_encode name);
            Buffer.add_char buf '=';
            Buffer.add_string buf (percent_encode value)
        | (name, value) :: rest ->
            Buffer.add_string buf (percent_encode name);
            Buffer.add_char buf '=';
            Buffer.add_string buf (percent_encode value);
            Buffer.add_char buf '&';
            add_headers rest
      in
      add_headers headers
  end;
  Buffer.add_char buf '>';
  Buffer.contents buf

let to_unstrctrd t =
  let str = to_string t ^ "\r\n" in
  let _, unstrctrd = Result.get_ok (Unstrctrd.of_string str) in
  unstrctrd

let of_unstrctrd t =
  let t = Unstrctrd.fold_fws t in
  let* t = Unstrctrd.without_comments t in
  let str = Unstrctrd.to_utf_8_string t in
  of_string str

let pp ppf t =
  Fmt.pf ppf "mailto:";
  begin match t.to_ with
  | [] -> ()
  | [ addr ] -> Fmt.pf ppf "%a" Emile.pp_mailbox addr
  | addr :: rest ->
      Fmt.pf ppf "%a" Emile.pp_mailbox addr;
      List.iter (fun a -> Fmt.pf ppf ",@ %a" Emile.pp_mailbox a) rest
  end;
  match t.headers with
  | [] -> ()
  | headers ->
      Fmt.pf ppf "?";
      let first = ref true in
      List.iter
        (fun (name, value) ->
          if !first then first := false else Fmt.pf ppf "&";
          Fmt.pf ppf "%s=%s" name value)
        headers

let compare_header (name0, value0) (name1, value1) =
  let v = String.compare name0 name1 in
  if v <> 0 then v else String.compare value0 value1

let compare a b =
  let v = List.compare Emile.compare_mailbox a.to_ b.to_ in
  if v <> 0 then v else List.compare compare_header a.headers b.headers

let equal a b = compare a b = 0
