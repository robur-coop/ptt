open Cmdliner

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let domain =
  let parser = Colombe.Domain.of_string in
  let pp = Fmt.of_to_string Colombe.Domain.to_string in
  Arg.conv (parser, pp) ~docv:"DOMAIN"

let zone =
  let parser = Mrmime.Date.Zone.of_string in
  let pp = Fmt.of_to_string Mrmime.Date.Zone.to_string in
  Arg.conv (parser, pp) ~docv:"ZONE"

let bytes_of_string s =
  let s = String.trim s in
  let len = String.length s in
  let rec find_non_digit i =
    if i >= len then i
    else if s.[i] >= '0' && s.[i] <= '9' then find_non_digit (i + 1)
    else i
  in
  let idx = find_non_digit 0 in
  let number_str = String.sub s 0 idx |> String.trim in
  let unit_str = String.sub s idx (len - idx) |> String.trim in
  let ( let* ) = Option.bind in
  let* number = int_of_string_opt number_str in
  let* multiplier =
    match String.lowercase_ascii unit_str with
    | "" | "b" -> Some 1
    | "kib" -> Some 1024
    | "mib" -> Some (1024 * 1024)
    | "gib" -> Some (1024 * 1024 * 1024)
    | "tib" -> Some (1024 * 1024 * 1024 * 1024)
    | _ -> None
  in
  Some (number * multiplier)

let sizes = [| "B"; "KiB"; "MiB"; "GiB"; "TiB" |]

let bytes_to_size = function
  | 0 -> "0b"
  | n ->
      let n = float_of_int n in
      let i = Float.floor (Float.log n /. Float.log 1024.) in
      let r = n /. Float.pow 1024. i in
      Fmt.str "%.0f%s" r sizes.(int_of_float i)

let size =
  let parser str =
    match bytes_of_string str with
    | Some n -> Ok n
    | None -> error_msgf "Invalid size: %S" str
  in
  Arg.conv (parser, Fmt.(using bytes_to_size string)) ~docv:"BYTES"

let domain =
  let doc = "The domain of the SMTP server." in
  let open Arg in
  required & opt (some domain) None & info [ "domain" ] ~doc ~docv:"DOMAIN"

let ipaddr =
  let v4 ipv4 = Ipaddr.V4 ipv4 in
  Term.map Ipaddr.(Fun.compose v4 V4.Prefix.address) Mnet_cli.ipv4

let zone =
  let doc = "The time zone in which the SMTP server is located." in
  let open Arg in
  value & opt zone Mrmime.Date.Zone.GMT & info [ "timezone" ] ~doc ~docv:"ZONE"

let size =
  let doc = "The maximum size of emails that can be accepted in bytes." in
  let open Arg in
  value & opt size 10485760 (* 10MiB *) & info [ "limit" ] ~doc ~docv:"BYTES"

let setup_server_info domain ipaddr zone size =
  { Ptt.domain; ipaddr; zone; size; tls= None }

let term_server_info =
  let open Term in
  const setup_server_info $ domain $ ipaddr $ zone $ size

let authenticator : (X509.Authenticator.t, [ `Msg of string ]) result Lazy.t =
  Lazy.from_fun Ca_certs_nss.authenticator

let tls_config user's_tls_config user's_authenticator =
  match user's_tls_config with
  | Some cfg -> Ok cfg
  | None ->
      let ( let* ) = Result.bind in
      let* authenticator =
        match (Lazy.force authenticator, user's_authenticator) with
        | Ok authenticator, None -> Ok authenticator
        | _, Some authenticator -> Ok authenticator
        | Error (`Msg msg), None -> Error (`Msg msg)
      in
      Tls.Config.client ~authenticator ()

let authenticator =
  let parser str =
    match X509.Authenticator.of_string str with
    | Ok authenticator -> Ok (authenticator, str)
    | Error _ as err -> err
  in
  let pp ppf (_, str) = Fmt.string ppf str in
  Arg.conv ~docv:"AUTHENTICATOR" (parser, pp)

let authenticator =
  let doc = "The TLS authenticator used to verify TLS certificates." in
  let open Arg in
  value
  & opt (some authenticator) None
  & info [ "a"; "auth"; "authenticator" ] ~doc ~docv:"AUTHENTICATOR"

let setup_client_info domain authenticator =
  let now = Fun.compose Option.some Mirage_ptime.now in
  let authenticator = Option.map (fun (fn, _) -> fn now) authenticator in
  let tls = tls_config None (* TODO *) authenticator in
  let tls = Result.get_ok tls in
  { Facteur.domain; tls= Some tls }

let term_client_info =
  let open Term in
  const setup_client_info $ domain $ authenticator

let setup_info server_info client_info = (server_info, client_info)

let term_info =
  let open Term in
  const setup_info $ term_server_info $ term_client_info
