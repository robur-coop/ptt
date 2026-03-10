let src = Logs.Src.create "facteur"

module Log = (val Logs.src_log src : Logs.LOG)
module Aggregate = Aggregate

type info = { domain: Colombe.Domain.t; tls: Tls.Config.client option }

(*
type email =
  { from : Reverse_path.t
  ; recipients : Forward_path.t list
  ; destination : string
  ; stream : string Flux.Stream.t }
*)

type buffers = bytes * bytes * (char, Bigarray.int8_unsigned_elt) Ke.Rke.t
type t = { he: Mnet_happy_eyeballs.t; pool: buffers Cattery.t }

let ( let* ) = Result.bind
let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

module Key = struct
  type t = Dns.Mx.t

  let compare { Dns.Mx.preference= a; _ } { Dns.Mx.preference= b; _ } =
    Int.compare a b
end

module Mxs = Map.Make (Key)

let mxs (Ptt.Resolver { dns; getmxbyname; gethostbyname }) = function
  | `Ipaddr ipaddr ->
      let mail_exchange = Ipaddr.to_domain_name ipaddr in
      let key = { Dns.Mx.preference= 0; mail_exchange } in
      Ok (Mxs.singleton key [ ipaddr ])
  | `Domain domain_name ->
      let* mxs = getmxbyname dns domain_name in
      let mxs = Dns.Rr_map.Mx_set.to_list mxs in
      let fn acc ({ Dns.Mx.mail_exchange; _ } as key) =
        match gethostbyname dns mail_exchange with
        | Ok ipaddrs -> Mxs.add key ipaddrs acc
        | Error _ -> acc
      in
      let mxs = List.fold_left fn Mxs.empty mxs in
      if Mxs.is_empty mxs then
        error_msgf "No SMTP server affiliated to %a" Domain_name.pp domain_name
      else Ok mxs

let sendmail t info resolver (from, { Aggregate.domain; locals }) seq =
  Cattery.use t.pool @@ fun (decoder, encoder, queue) ->
  let encoder = Fun.const encoder
  and decoder = Fun.const decoder
  and queue = Fun.const queue
  and recipients =
    let open Colombe in
    let open Forward_path in
    let domain =
      match domain with
      | `Ipaddr (Ipaddr.V4 v4) -> Domain.IPv4 v4
      | `Ipaddr (Ipaddr.V6 v6) -> Domain.IPv6 v6
      | `Domain v -> Domain.Domain (Domain_name.to_strings v)
    in
    let local_to_forward_path local =
      let local = List.map (function `Atom x -> x | `String x -> x) local in
      Forward_path { Path.local= `Dot_string local; domain; rest= [] }
    in
    match locals with
    | `All -> [ Domain domain ]
    | `Some locals -> List.map local_to_forward_path locals
    | `Postmaster -> [ Postmaster ]
  in
  let* mxs = mxs resolver domain in
  let mxs = Mxs.bindings mxs in
  let rec go seq dsts =
    match (dsts, Seq.uncons seq) with
    | [], _ -> assert false
    | _, None -> assert false
    | [ (_mx, ipaddrs) ], Some (stream, _) ->
        Log.debug (fun m ->
            m "try to send email to: @[<hov>%a@]"
              Fmt.(Dump.list Ipaddr.pp)
              ipaddrs);
        let destination = `Ips ipaddrs in
        let fn str = (str, 0, String.length str) in
        let stream = Flux.Stream.map fn stream in
        Msendmail.sendmail ~encoder ~decoder ~queue t.he ~destination
          ~domain:info.domain ?cfg:info.tls from recipients stream
    | (_mx, ipaddrs) :: mxs, Some (stream, seq) -> begin
        let destination = `Ips ipaddrs in
        let fn str = (str, 0, String.length str) in
        let stream = Flux.Stream.map fn stream in
        let result =
          Msendmail.sendmail ~encoder ~decoder ~queue t.he ~destination
            ~domain:info.domain ?cfg:info.tls from recipients stream
        in
        match result with Ok _ as value -> value | Error _ -> go seq mxs
      end
  in
  go seq mxs

let sendmail t ~info resolver ~from recipients seq =
  let recipients = Aggregate.to_recipients ~domain:info.domain recipients in
  Log.debug (fun m ->
      m "send email to: @[<hov>%a@]" Fmt.(Dump.list Aggregate.pp) recipients);
  let fn recipients =
    Miou.async @@ fun () ->
    let result = sendmail t info resolver (from, recipients) seq in
    (recipients, result)
  in
  let prms = List.map fn recipients in
  let results = Miou.await_all prms in
  let fn = function
    | Ok (_, Ok ()) -> ()
    | Ok (recipients, Error err) ->
        Log.err (fun m ->
            m "Impossible to send an email to %a: %a" Aggregate.pp recipients
              Msendmail.pp_error err)
    | Error exn ->
        Log.err (fun m -> m "Got an exception: %s" (Printexc.to_string exn))
  in
  List.iter fn results
