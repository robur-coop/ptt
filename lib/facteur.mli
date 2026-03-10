type info = { domain: Colombe.Domain.t; tls: Tls.Config.client option }
type buffers = bytes * bytes * (char, Bigarray.int8_unsigned_elt) Ke.Rke.t
type t = { he: Mnet_happy_eyeballs.t; pool: buffers Cattery.t }

val sendmail :
     t
  -> info:info
  -> Ptt.resolver
  -> from:Colombe.Reverse_path.t
  -> Colombe.Forward_path.t list
  -> string Flux.stream Seq.t
  -> unit
