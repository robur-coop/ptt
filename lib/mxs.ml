type key = Dns.Mx.t

module Key = struct
  type t = key

  let compare { Dns.Mx.preference= a; _ } { Dns.Mx.preference= b; _ } =
    Int.compare a b
end

include (Map.Make (Key) : Map.S with type key := key)

let v ~preference ~domain:mail_exchange ipaddr =
  singleton { preference; mail_exchange } ipaddr

let vs =
  let fn acc (mx, ipaddr) = add mx ipaddr acc in
  List.fold_left fn empty
