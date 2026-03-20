(** Facteur - Email delivery over SMTP.

    This module provides high-level functions for sending emails via SMTP with
    STARTTLS support. It handles MX record resolution, connection pooling, and
    failover across multiple mail exchangers ordered by preference. *)

module Aggregate = Aggregate

(** {1 Types} *)

type info = { domain: Colombe.Domain.t; tls: Tls.Config.client option }
(** Sender information. [domain] is the domain announced during the SMTP [EHLO]
    handshake. [tls] is the optional TLS client configuration used for STARTTLS
    negotiation. *)

type buffers = bytes * bytes * (char, Bigarray.int8_unsigned_elt) Ke.Rke.t
(** Internal buffers used for SMTP encoder, decoder, and queue. Managed through
    a {!Cattery} pool to avoid repeated allocation. *)

type t = { he: Mnet_happy_eyeballs.t; pool: buffers Cattery.t }
(** The sending context. [he] is the Happy Eyeballs connection manager and
    [pool] is a bounded pool of reusable {!buffers}. *)

type error = [ `Msg of string | Sendmail_with_starttls.error ]
(** The type of errors. Either a human-readable message or a lower-level
    SMTP/STARTTLS protocol error. *)

val pp_error : error Fmt.t

(** {1 Sending functions} *)

val sendmail :
     t
  -> info:info
  -> Ptt.resolver
  -> from:Colombe.Reverse_path.t
  -> Colombe.Forward_path.t list
  -> string Flux.stream Seq.t
  -> (Aggregate.destination * error) list
(** [sendmail t ~info resolver ~from recipients email] sends [email] from [from]
    to [recipients]. Recipients are grouped by destination domain and each group
    is delivered concurrently via {!Miou.async}. The mail exchangers for each
    domain are resolved through [resolver] and tried in order of MX preference.

    [email] is a {!Seq.t} of {!Flux.stream} values: each element of the sequence
    is a replayable copy of the email body, consumed once per MX attempt (to
    allow failover).

    Returns a list of [(destination, error)] pairs for each destination group
    that failed. An empty list means all deliveries succeeded.

    @raise Invalid_argument if [recipients] is empty. *)

val many :
     t
  -> info:info
  -> Ptt.resolver
  -> destination:Colombe.Domain.t
  -> (Colombe.Reverse_path.t * Colombe.Forward_path.t list) list
  -> string Flux.stream Seq.t
  -> ((unit, error) result list, error) result
(** [many t ~info resolver ~destination txs email] sends multiple transactions
    [txs] to the same [destination] domain within a single SMTP session. Each
    transaction is a [(from, recipients)] pair.

    [email] is a sequence of streams — one stream per transaction is consumed
    from it (via {!Seq.take}).

    Returns [Ok results] where each element indicates the success or failure of
    the corresponding transaction, or [Error _] if no MX server could be reached
    at all. MX servers are tried in order of preference with failover.

    @raise Invalid_argument if [txs] is empty.
    @raise Invalid_argument
      if any recipient in [txs] has a domain that does not match [destination].
*)

val broadcast :
     t
  -> info:info
  -> Ptt.resolver
  -> from:Colombe.Reverse_path.t
  -> Colombe.Forward_path.t list
  -> string Flux.stream Seq.t
  -> (Colombe.Domain.t * error) list
(** [broadcast t ~info resolver ~from recipients email] sends [email] from
    [from] to [recipients], grouped by destination domain, with each domain
    delivered concurrently. Unlike {!sendmail} which groups by
    {!Aggregate.destination}, [broadcast] groups directly by
    {!Colombe.Domain.t}.

    Returns a list of [(domain, error)] pairs for each domain where at least one
    recipient delivery failed. An empty list means all deliveries succeeded.
    Recipients with no extractable domain (e.g. [Postmaster]) are silently
    dropped.

    @raise Invalid_argument if [recipients] is empty. *)
