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

type t = {
    failures: (Colombe.Path.t, int list) Hashtbl.t
  ; possibly_fixed: Cache.t
}

let create () =
  let failures = Hashtbl.create 0x7ff in
  let possibly_fixed = Cache.create 0x7ff in
  { failures; possibly_fixed }

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
