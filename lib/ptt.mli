open Colombe

type info = {
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

type ('dns, 'err) getmxbyname =
     'dns
  -> [ `host ] Domain_name.t
  -> (Dns.Rr_map.Mx_set.t, ([> `Msg of string ] as 'err)) result

type ('dns, 'err) gethostbyname =
     'dns
  -> [ `host ] Domain_name.t
  -> (Ipaddr.t list, ([> `Msg of string ] as 'err)) result

type resolver =
  | Resolver : {
        getmxbyname: 'err. ('dns, 'err) getmxbyname
      ; gethostbyname: 'err. ('dns, 'err) gethostbyname
      ; dns: 'dns
    }
      -> resolver

exception Recipients_unreachable

type user's_error =
  [ `Aborted
  | `Not_enough_memory
  | `Too_big_data
  | `Failed
  | `Requested_action_not_taken of [ `Temporary | `Permanent ] ]

type oc = [ `Ok | user's_error ] Miou.Computation.t

module Relay : sig
  type error
  type ic = email Miou.Computation.t

  val pp_error : error Fmt.t

  val handler :
       ?encoder:(unit -> bytes)
    -> ?decoder:(unit -> bytes)
    -> ?queue:(unit -> (char, Bigarray.int8_unsigned_elt) Ke.Rke.t)
    -> info:info
    -> resolver
    -> Mnet.TCP.flow
    -> ic * oc
    -> (string, 'r) Flux.Bqueue.t
    -> (unit, error) result
end

module Submission : sig
  type ic = (string * email) Miou.Computation.t
  type error
  type authenticator = ?payload:string -> Mechanism.t -> string * bool
  type authentication = Mechanism.t list * authenticator

  val handler :
       ?encoder:(unit -> bytes)
    -> ?decoder:(unit -> bytes)
    -> info:info
    -> resolver
    -> authentication
    -> Mnet_tls.t
    -> ic * oc
    -> (string, 'r) Flux.Bqueue.t
    -> (unit, error) result
end
