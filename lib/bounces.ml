let src = Logs.Src.create "bounces"

module Log = (val Logs.src_log src : Logs.LOG)

module Key = struct
  include Colombe.Path

  let hash = Hashtbl.hash
end

module Value = struct
  type t = { expire_at: Ptime.t; attempts: int list }

  let weight _ = 1
end

module Cache = Lru.M.Make (Key) (Value)
module S = Map.Make (String)

type t = {
    failures: (Colombe.Path.t, int list) Hashtbl.t
  ; possibly_fixed: Cache.t
  ; store: t -> unit
}

(*

  let failures =
    let fn k v m = S.add (Colombe.Path.Encoder.to_string k) v m in
    Hashtbl.fold fn t.failures S.empty in
  let possibly_fixed =
    let fn k v m = S.add (Colombe.Path.Encore.to_string k) v m in
    Cache.fold fn S.empty t.possibly_fixed in
  let open Jsont in
  let fn m0 m1 = (m0, m1) in
    let failures = Hashtbl.create 0x7ff in
    let possibly_fixed = Cache.create 0x7ff in
    let fn path attempts =
      let path = Colombe.Path.of_string_exn path in
      Hashtbl.replace failures path attempts in
    S.iter fn m0;
    let fn path { expire_at; attempts } =
      if not (Ptime.is_earlier expire_at ~than:now)
      then Cache.add path value possibly_fixed in
    { failures; possibly_fixed } in


 *)

let rfc3339 =
  let dec str =
    match Ptime.of_rfc3339 str with
    | Ok (t, _tz, _) -> t
    | Error _ -> Fmt.failwith "Invalid RFC3339 date"
  in
  let enc = Ptime.to_rfc3339 in
  Jsont.map ~dec ~enc Jsont.string

let json =
  let open Jsont in
  let value =
    Object.map (fun expire_at attempts -> { Value.expire_at; attempts })
    |> Object.mem "expire_at" ~enc:(fun v -> v.Value.expire_at) rfc3339
    |> Object.mem "attempts" ~enc:(fun v -> v.Value.attempts) (list int)
    |> Object.finish
  in
  Object.map (fun m0 m1 -> (m0, m1))
  |> Object.mem "failures" ~enc:fst (Object.as_string_map (list int))
  |> Object.mem "possibly_fixed" ~enc:snd (Object.as_string_map value)
  |> Object.finish

let json ?(store = ignore) () =
  let now = Mirage_ptime.now () in
  let enc t =
    let fn0 k v m = S.add (Colombe.Path.Encoder.to_string k) v m in
    let m0 = Hashtbl.fold fn0 t.failures S.empty in
    let fn1 k v m = S.add (Colombe.Path.Encoder.to_string k) v m in
    let m1 = Cache.fold fn1 S.empty t.possibly_fixed in
    (m0, m1)
  in
  let dec (m0, m1) =
    let failures = Hashtbl.create 0x7ff in
    let possibly_fixed = Cache.create 0x7ff in
    let fn path attempts =
      let path = Colombe.Path.of_string_exn path in
      Hashtbl.replace failures path attempts
    in
    S.iter fn m0;
    let fn path ({ Value.expire_at; _ } as value) =
      let path = Colombe.Path.of_string_exn path in
      if not (Ptime.is_earlier expire_at ~than:now) then
        Cache.add path value possibly_fixed
    in
    S.iter fn m1;
    { failures; possibly_fixed; store }
  in
  Jsont.map ~dec ~enc json

let create ?(store = ignore) () =
  let failures = Hashtbl.create 0x7ff in
  let possibly_fixed = Cache.create 0x7ff in
  { failures; possibly_fixed; store }

let failure_for t ~counter path =
  match Hashtbl.find_opt t.failures path with
  | Some attempts when List.length attempts < 3 ->
      let attempts = List.sort_uniq Int.compare (counter :: attempts) in
      Hashtbl.replace t.failures path attempts;
      None
  | Some _ ->
      Log.debug (fun m -> m "Too many failures for: %a" Colombe.Path.pp path);
      Hashtbl.remove t.failures path;
      Some path
  | None ->
      Hashtbl.add t.failures path [ counter ];
      None

let _15m = Ptime.Span.of_int_s 900

let success_for t ~counter path =
  match Hashtbl.find_opt t.failures path with
  | None -> ()
  | Some attempts ->
      Log.debug (fun m ->
          m "A possible success for %a, put it into our cache" Colombe.Path.pp
            path);
      let now = Mirage_ptime.now () in
      let expire_at = Ptime.add_span now _15m in
      let expire_at = Option.get expire_at in
      let attempts = List.sort_uniq Int.compare (counter :: attempts) in
      Hashtbl.remove t.failures path;
      Cache.add path { expire_at; attempts } t.possibly_fixed

let rec clean_up t =
  let than = Mirage_ptime.now () in
  match Cache.lru t.possibly_fixed with
  | Some (path, { expire_at; _ }) when Ptime.is_earlier expire_at ~than ->
      Cache.remove path t.possibly_fixed;
      clean_up t
  | Some _ -> ()
  | None -> ()

let signaled_for t ~counter path =
  clean_up t;
  match Cache.find path t.possibly_fixed with
  | Some { attempts; _ } ->
      let attempts = List.sort_uniq Int.compare (counter :: attempts) in
      Log.debug (fun m -> m "%a failed, re-add it" Colombe.Path.pp path);
      Hashtbl.replace t.failures path attempts;
      Cache.remove path t.possibly_fixed
  | None ->
      begin match Hashtbl.find_opt t.failures path with
      | Some attempts when List.length attempts < 3 ->
          let attempts = List.sort_uniq Int.compare (counter :: attempts) in
          Hashtbl.replace t.failures path attempts
      | Some attempts ->
          let len = List.length attempts in
          let attempts = List.sort_uniq Int.compare (counter :: attempts) in
          let attempts = List.drop (len - 3) attempts in
          Hashtbl.replace t.failures path attempts
      | None -> Hashtbl.add t.failures path [ counter ]
      end
