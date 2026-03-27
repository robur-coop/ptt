type t

val create : unit -> t
val failure_for : t -> counter:int -> Colombe.Path.t -> Colombe.Path.t option
val success_for : t -> counter:int -> Colombe.Path.t -> unit
val signaled_for : t -> counter:int -> Colombe.Path.t -> unit
