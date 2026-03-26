(*
(** Mailing List Manager *)

type who = Moderators | Subscribers | Public
type subscription_status = Awaiting_moderation | Awaiting_confirmation

type t = {
    name: string
  ; domain: Colombe.Domain.t
  ; moderators: Colombe.Path.t list
  ; subscribers: Colombe.Path.t list
  ; pending_subscriptions:
      (subscription_status * string (* id *) * Colombe.Path.t) list
  ; subscription_moderated: bool
  ; moderated: bool
  ; who_can_post: who
  ; who_is_moderated: who
  ; pending_mails:
      (string (* id *) * Colombe.Path.t (* original_from *) * Bstr.t (* mail *))
      list
  ; bounces: (int (* counter *) * int (* score *) * Colombe.Path.t) list
  ; counter: int
  ; footer: string option
}
*)

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

type outgoing = {
    sender: Colombe.Reverse_path.t
  ; recipients: Colombe.Forward_path.t list
  ; seq: string Flux.stream Seq.t
}

type tx = { sender: Colombe.Reverse_path.t; recipient: Colombe.Forward_path.t }
type error = [ `Msg of string ]

val failure_for :
     t
  -> from:Colombe.Reverse_path.t
  -> Colombe.Path.t
  -> (unit, [> `Msg of string ]) result

val outgoing :
     t
  -> from:Colombe.Reverse_path.t
  -> rcpt:Colombe.Path.t
  -> (t * tx list, error) result

val incoming :
     t
  -> from:Colombe.Reverse_path.t
  -> rcpt:Colombe.Path.t
  -> Bstr.t
  -> (t * outgoing list * outgoing list, error) result
