type t = X509.Certificate.t * X509.Private_key.t * X509.Authenticator.t

val make : string -> seed:string -> (t, [> `Msg of string ]) result

val self_signed :
     Ptt.info
  -> seed:string
  -> (Tls.Config.server * Ptime.t option, [> `Msg of string ]) result

val tls :
     Mnet.TCP.state
  -> Ptt.info
  -> string option
  -> ((Ipaddr.t * int) * ('a Domain_name.t * Dns.Dnskey.t) * string) option
  -> (Tls.Config.server * Ptime.t option, [> Cert.error ]) result
