type t

val make : ?headers:(string * string) list -> Emile.mailbox list -> t
val to_ : t -> Emile.mailbox list
val headers : t -> (string * string) list
val subject : t -> string option
val body : t -> string option

(**/*)

val of_string : string -> (t, [> `Msg of string ]) result
val to_string : t -> string
val of_unstrctrd : Unstrctrd.t -> (t, [> `Msg of string ]) result
val to_unstrctrd : t -> Unstrctrd.t

(**/*)

val pp : Format.formatter -> t -> unit
val equal : t -> t -> bool
val compare : t -> t -> int
