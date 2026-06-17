(** A Milter (mail filter) server implementation.

    This module implements the wire protocol used by Sendmail/Postfix to
    communicate with external mail filters ({i milters}). This implementation
    focus what on what is required for [nec]: sign incoming emails. The module
    also follows what [Ptt.{Relay,Submission}] provides. *)

type info = Ptt.info
type email = Ptt.email
type ic = email Miou.Computation.t

type decision =
  [ `Continue | `Accept | `Reject | `Tempfail | `Add_header of string * string ]
(** A milter's decision for the current message. [`Add_header (name, value)]
    asks the MTA to add a header field (the value must not contain the field
    name nor a trailing newline). The other constructors map to the
    corresponding milter reply codes. *)

type oc = decision Miou.Computation.t
type error = [ `Closed | `Protocol of string ]

val pp_error : error Fmt.t

module Wire : sig
  val packet : char -> string -> string
  val cstring : string -> int -> string * int
  val optneg_response : string -> string
  val add_header : name:string -> value:string -> string
end

val handler :
     ?encoder:(unit -> bytes)
  -> ?decoder:(unit -> bytes)
  -> ?queue:(unit -> (char, Bigarray.int8_unsigned_elt) Ke.Rke.t)
  -> info:info
  -> Mnet.TCP.flow
  -> ic * oc
  -> (string, 'r) Flux.Bqueue.t
  -> (unit, error) result
(** [handler ~info flow (ic, oc) q] speaks the milter protocol on [flow] for a
    single message. It fills [ic] with the {!type:email} as soon as the message
    starts, reconstructs the RFC 5322 message (each header as [name: value\r\n],
    a blank line, then the body chunks) into [q], and on end-of-body waits for
    the signer's decision on [oc] before answering the MTA.

    The optional [encoder]/[decoder]/[queue] arguments are accepted for symmetry
    with {!Ptt.{Relay,Submission}.handler}. *)
