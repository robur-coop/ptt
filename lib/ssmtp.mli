open Colombe.State
open Colombe

module Value : sig
  include module type of Logic.Value

  type decoder = Decoder.decoder
  type encoder = Encoder.encoder

  val encode : encoder -> 'x send -> 'x -> (unit, [> Reply.Encoder.error ]) t
  val decode : decoder -> 'x recv -> ('x, [> Request.Decoder.error ]) t
end

type info = Logic.info = {
    domain: Domain.t
  ; ipaddr: Ipaddr.t
  ; tls: Tls.Config.server option
  ; zone: Mrmime.Date.Zone.t
  ; size: int
}

type email = Logic.email = {
    from: Reverse_path.t * (string * string option) list
  ; recipients: (Forward_path.t * (string * string option) list) list
  ; domain_from: Domain.t
}

module Monad : module type of State.Scheduler (Context) (Value)

type context = Context.t

module R : sig
  type quit = [ `Quit ]
  type relay = [ quit | `Send of email ]

  type submission =
    [ quit
    | `Authentication of Domain.t * Mechanism.t
    | `Authentication_with_payload of Domain.t * Mechanism.t * string ]
end

module Action : sig
  type t =
    [ `Aborted
    | `Not_enough_memory
    | `Too_big_data
    | `Failed
    | `Requested_action_not_taken of [ `Temporary | `Permanent ]
    | `Ok ]
end

type error =
  [ `No_recipients
  | `Protocol of Value.error
  | `Too_many_bad_commands
  | `Too_many_recipients ]

val pp_error : error Fmt.t

val m_properly_close_and_fail :
  context -> ?code:int -> string -> (unit, [> error ]) State.t

val m_politely_close : context -> ([> R.quit ], [> error ]) State.t

val m_submission :
     context
  -> domain_from:Domain.t
  -> Mechanism.t list
  -> ([> R.submission ], [> error ]) State.t

val m_relay :
  context -> domain_from:Domain.t -> ([> R.relay ], [> error ]) State.t

val m_mail : context -> (unit, [> error ]) State.t
val m_end : Action.t -> context -> ([> R.quit ], [> error ]) State.t
val m_relay_init : context -> info -> ([> R.relay ], [> error ]) State.t

val m_submission_init :
  context -> info -> Mechanism.t list -> ([> R.submission ], [> error ]) State.t
