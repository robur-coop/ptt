type t

val create : ?store:(t -> unit) -> unit -> t
val json : ?store:(t -> unit) -> unit -> t Jsont.t
val failure_for : t -> counter:int -> Colombe.Path.t -> Colombe.Path.t option
val failure_for_without_deletion : t -> counter:int -> Colombe.Path.t -> unit
val success_for : t -> counter:int -> Colombe.Path.t -> unit
val signaled_for : t -> counter:int -> Colombe.Path.t -> unit
