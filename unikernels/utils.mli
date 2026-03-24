type error =
  [ Dmarc.Verify.error
  | `Invalid_email
  | `Not_enough
  | `Invalid_domain_key of Arc.t
  | `Missing_authentication_results ]

val pp_error : error Fmt.t

val dkim :
     key:Dkim.key
  -> Dkim.unsigned Dkim.t
  -> (string, (Dkim.signed Dkim.t, [> error ]) result) Flux.sink

type field = Mrmime.Field_name.t * Unstrctrd.t

val headers : (string, (field list, [> error ]) result) Flux.sink

type dmarc = Dmarc.Verify.info * Dmarc.DKIM.t list * [ `Fail | `Pass ]

val dmarc :
  ctx:Uspf.ctx -> Mnet_dns.t -> (string, (dmarc, [> error ]) result) Flux.sink

val chain :
  Mnet_dns.t -> (string, (Arc.Verify.chain, [> error ]) result) Flux.sink

val arc :
     seal:Arc.Sign.seal
  -> msgsig:Dkim.unsigned Dkim.t
  -> receiver:Emile.domain
  -> ?results:Arc.Sign.user's_results
  -> Arc.key * Arc.key option
  -> [ `Verified of Arc.Verify.chain | `Unverified of Arc.Sign.user's_chain ]
  -> (string, (Arc.Sign.set, [> error ]) result) Flux.sink

val save_into : Bstr.t -> (string, Bstr.t) Flux.sink
val from_bstr : ?len:int -> Bstr.t -> string Flux.source
val chain_from_headers : field list -> Arc.Sign.user's_chain
