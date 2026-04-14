let ( let* ) = Result.bind
let failwithf fmt = Fmt.kstr failwith fmt
let msg msg = `Msg msg
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Blk = struct
  external getpagesize : unit -> int = "ptt_getpagesize" [@@noalloc]

  external pread :
    Unix.file_descr -> Bstr.t -> off:int -> len:int -> at:int -> int
    = "ptt_pread"

  external pwrite :
    Unix.file_descr -> Bstr.t -> off:int -> len:int -> at:int -> int
    = "ptt_pwrite"

  type t = Unix.file_descr

  let pagesize _ = getpagesize ()

  let read fd ~src_off ?(dst_off = 0) bstr =
    let len = Bstr.length bstr - dst_off in
    ignore (pread fd bstr ~off:dst_off ~len ~at:src_off)

  let write fd ?(src_off = 0) ~dst_off bstr =
    let len = Bstr.length bstr - src_off in
    let ret = pwrite fd bstr ~off:src_off ~len ~at:dst_off in
    if ret < len then
      failwithf "Impossible to write %d byte(s) at %d" len dst_off
end

module Bos = Mfat_bos.Make (Blk)

let temp_json = Fpath.v "temp.json"
let bounces_json = Fpath.v "bounces.json"

let serialize t filepath json value =
  let str = Jsont_bytesrw.encode_string json value in
  let* str = Result.map_error msg str in
  Bos.File.write t filepath str

let create _quiet filepath total_sectors =
  let fd =
    Unix.openfile (Fpath.to_string filepath) Unix.[ O_CREAT; O_RDWR ] 0o644
  in
  let finally () = Unix.close fd in
  Fun.protect ~finally @@ fun () ->
  Bos.format fd ~total_sectors;
  let* t = Bos.create fd in
  let bounces = Bounces.create () in
  let* _ = Bos.Dir.create t ~path:true (Fpath.v "lists") in
  let* _ = Bos.Dir.create t ~path:true (Fpath.v "tmp") in
  let* () = serialize t bounces_json (Bounces.json ()) bounces in
  let* () = serialize t temp_json Jsont.(list (null ())) [] in
  Ok ()

let add _quiet domain filepath moderators subscribers name =
  let fd = Unix.openfile (Fpath.to_string filepath) Unix.[ O_RDWR ] 0o644 in
  let finally () = Unix.close fd in
  Fun.protect ~finally @@ fun () ->
  let* t = Bos.create fd in
  let dst = Fpath.add_ext "json" Fpath.(v "lists" / Mlm.local_to_string name) in
  let* exists = Bos.File.exists t dst in
  if exists then
    error_msgf "%s already exists, you can set or remove it"
      (Mlm.local_to_string name)
  else
    let json = Mlm.json ~domain name in
    let list = Mlm.make ~domain name in
    let list = List.fold_left Mlm.add_moderator list moderators in
    let list = List.fold_left Mlm.add_subscriber list subscribers in
    let* () = serialize t dst json list in
    Ok ()

let deserialize t filepath json =
  let* str = Bos.File.read t filepath in
  Jsont_bytesrw.decode_string json str |> Result.map_error msg

let show _quiet domain filepath =
  let fd = Unix.openfile (Fpath.to_string filepath) Unix.[ O_RDWR ] 0o644 in
  let finally () = Unix.close fd in
  Fun.protect ~finally @@ fun () ->
  let* t = Bos.create fd in
  let* temp_exists = Bos.exists t temp_json in
  let* temps =
    if temp_exists then deserialize t temp_json Temp.list else Ok []
  in
  let* lists =
    let fn filepath =
      let bname = Fpath.(basename (rem_ext filepath)) in
      let* local = Mlm.local_of_string bname in
      let local = Colombe_emile.of_local local in
      let json = Mlm.json ~domain local in
      deserialize t filepath json
    in
    let fn filepath acc =
      match fn filepath with
      | Ok list -> list :: acc
      | Error _ ->
          Logs.warn (fun m ->
              m "%a is not a valid JSON object to describe a list, ignore it"
                Fpath.pp filepath);
          acc
    in
    Bos.fold ~elements:`Files ~traverse:`Any t fn [] [ Fpath.v "lists/" ]
  in
  let* bounces_exists = Bos.exists t bounces_json in
  let* _bounces =
    if bounces_exists then deserialize t bounces_json (Bounces.json ())
    else Ok (Bounces.create ())
  in
  Fmt.pr "Temporary emails: %d\n%!" (List.length temps);
  Fmt.pr "Lists: %d\n%!" (List.length lists);
  Ok ()

open Cmdliner

let output_options = "OUTPUT OPTIONS"

let verbosity =
  let env = Cmd.Env.info "BLAZE_LOGS" in
  Logs_cli.level ~docs:output_options ~env ()

let renderer =
  let env = Cmd.Env.info "BLAZE_FMT" in
  Fmt_cli.style_renderer ~docs:output_options ~env ()

let utf_8 =
  let doc = "Allow binaries to emit UTF-8 characters." in
  let env = Cmd.Env.info "BLAZE_UTF_8" in
  Arg.(value & opt bool true & info [ "with-utf-8" ] ~doc ~env)

let reporter ppf =
  let report src level ~over k msgf =
    let k _ = over (); k () in
    let with_metadata header _tags k ppf fmt =
      Fmt.kpf k ppf
        ("[%a]%a[%a]: " ^^ fmt ^^ "\n%!")
        Fmt.(styled `Cyan int)
        (Stdlib.Domain.self () :> int)
        Logs_fmt.pp_header (level, header)
        Fmt.(styled `Magenta string)
        (Logs.Src.name src)
    in
    msgf @@ fun ?header ?tags fmt -> with_metadata header tags k ppf fmt
  in
  { Logs.report }

let setup_logs utf_8 style_renderer level =
  Fmt_tty.setup_std_outputs ~utf_8 ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (reporter Fmt.stderr);
  Option.is_none level

let setup_logs = Term.(const setup_logs $ utf_8 $ renderer $ verbosity)

let filepath =
  let parser str =
    match Fpath.of_string str with
    | Ok v when Sys.file_exists str = false -> Ok v
    | Ok v -> error_msgf "%a already exists" Fpath.pp v
    | Error _ as err -> err
  in
  let doc = "The FAT32 image used by the unikernel." in
  let open Arg in
  required
  & pos 0 (some (conv (parser, Fpath.pp))) None
  & info [] ~doc ~docv:"IMAGE"

let total_sectors =
  let doc = "The total number of sectors (512 bytes per each)." in
  let open Arg in
  value & opt int 2048 & info [ "s"; "sectors" ] ~doc ~docv:"NUMBER"

let domain =
  let parser = Colombe.Domain.of_string in
  let pp = Fmt.of_to_string Colombe.Domain.to_string in
  Arg.conv (parser, pp) ~docv:"DOMAIN"

let domain =
  let doc = "The domain of the SMTP server." in
  let open Arg in
  required & opt (some domain) None & info [ "domain" ] ~doc ~docv:"DOMAIN"

let term_create =
  let open Term in
  const create
  $ setup_logs
  $ filepath
  $ total_sectors
  |> term_result ~usage:false

let cmd_create =
  let doc = "Create an image for $(b,ptt) unikernels." in
  let man = [] in
  let info = Cmd.info "create" ~doc ~man in
  Cmd.v info term_create

let filepath =
  let parser str =
    match Fpath.of_string str with
    | Ok v when Sys.file_exists str && Sys.is_regular_file str -> Ok v
    | Ok v -> error_msgf "%a does not exist" Fpath.pp v
    | Error _ as err -> err
  in
  let doc = "The FAT32 image used by unikernels." in
  let open Arg in
  required
  & pos 0 (some (conv (parser, Fpath.pp))) None
  & info [] ~doc ~docv:"IMAGE"

let spath =
  let parser = Colombe.Path.of_string in
  let pp = Colombe.Path.pp in
  Arg.conv (parser, pp) ~docv:"EMAIL"

let moderators =
  let doc = "Moderators of the given mailing list." in
  let open Arg in
  non_empty & opt_all spath [] & info [ "m"; "moderator" ] ~doc ~docv:"EMAIL"

let subscribers =
  let doc = "Subscribers of the given mailing list." in
  let open Arg in
  value & opt_all spath [] & info [ "s"; "subscriber" ] ~doc ~docv:"EMAIL"

let local =
  let parser str =
    Result.map Colombe_emile.of_local (Mlm.local_of_string str)
  in
  let pp = Fmt.using Mlm.local_to_string Fmt.string in
  Arg.conv (parser, pp) ~docv:"NAME"

let name =
  let doc = "The name of the mailing list." in
  let open Arg in
  required & pos 1 (some local) None & info [] ~doc ~docv:"NAME"

let term_add =
  let open Term in
  const add
  $ setup_logs
  $ domain
  $ filepath
  $ moderators
  $ subscribers
  $ name
  |> term_result ~usage:false

let cmd_add =
  let doc = "Add a new mailing list into the given FAT32 image." in
  let man = [] in
  let info = Cmd.info "add" ~doc ~man in
  Cmd.v info term_add

let term_show =
  let open Term in
  const show $ setup_logs $ domain $ filepath |> term_result ~usage:false

let cmd_show =
  let doc =
    "Show the current state of a mailing list from the given FAT32 image."
  in
  let man = [] in
  let info = Cmd.info "show" ~doc ~man in
  Cmd.v info term_show

let default =
  let open Term in
  ret (const (`Help (`Pager, None)))

let () =
  let doc = "A tool to prepare image required by $(b,ptt) unikernels." in
  let man = [] in
  let info = Cmd.info "ptt" ~doc ~man in
  let cmd = Cmd.group info ~default [ cmd_create; cmd_add; cmd_show ] in
  Cmd.(exit (eval cmd))
