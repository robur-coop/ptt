(** Mailing List Manager *)

val local_to_string : Emile.local -> string

val local_of_string :
     string
  -> ( [ `Dot_string of string list | `String of string ]
     , [> `Msg of string ] )
     result

type t

val make : domain:Colombe.Domain.t -> Emile.local -> t
val to_emile : t -> Emile.mailbox

val json :
  ?store:(t -> unit) -> domain:Colombe.Domain.t -> Emile.local -> t Jsont.t

val name : t -> string
val domain : t -> Colombe.Domain.t
val subscribers : t -> Colombe.Path.t list
val add_moderator : t -> Colombe.Path.t -> t
val add_subscriber : t -> Colombe.Path.t -> t
val with_subscribers : t -> Colombe.Path.t list -> t
val with_moderators : t -> Colombe.Path.t list -> t
val moderators : t -> Colombe.Path.t list
val save : t -> unit

type outgoing = {
    sender: Colombe.Reverse_path.t
  ; recipients: Colombe.Forward_path.t list
  ; seq: string Flux.stream Seq.t
}

type tx = { sender: Colombe.Reverse_path.t; recipient: Colombe.Forward_path.t }

val outgoing :
     t
  -> from:Colombe.Reverse_path.t
  -> rcpt:Colombe.Path.t
  -> (t * int * tx list, [> `Msg of string ]) result

val incoming :
     t
  -> Bounces.t
  -> from:Colombe.Reverse_path.t
  -> rcpt:Colombe.Path.t
  -> Bstr.t
  -> (t * outgoing list * outgoing list, [ `Msg of string ]) result
