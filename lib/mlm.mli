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

(*
val who_to_string : who -> string
val who_of_string : string -> (who, [> `Msg of string ]) result

val make :
     ?subscription_moderated:bool
  -> ?moderated:bool
  -> ?who_can_post:who
  -> ?who_is_moderated:who
  -> ?footer:string
  -> name:string
  -> domain:Colombe.Domain.t
  -> moderators:Colombe.Path.t list
  -> unit
  -> t

val path_to_string : Colombe.Path.t -> string
val path_of_string : string -> Colombe.Path.t option
val is_loop : t -> Bstr.t -> bool
*)

type error = [ `Msg of string ]

val incoming :
     t
  -> from:Colombe.Reverse_path.t
  -> rcpt:Colombe.Path.t
  -> Bstr.t
  -> (t * outgoing list * outgoing list, error) result
