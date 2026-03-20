type error =
  [ `Bad_reply of Dns.Packet.mismatch * Dns.Packet.t
  | `Decode of Dns.Packet.err
  | `Msg of string
  | `No_tlsa
  | `Tsig of Dns_tsig.e
  | `Unexpected_reply of Dns.Packet.reply ]

val retrieve_certificate :
     Mnet.TCP.state
  -> 'a Domain_name.t * Dns.Dnskey.t
  -> hostname:[ `host ] Domain_name.t
  -> ?additional_hostnames:[ `raw ] Domain_name.t list
  -> ?key_type:X509.Key_type.t
  -> ?key_data:string
  -> ?key_seed:string
  -> ?bits:int
  -> Ipaddr.t
  -> int
  -> (X509.Certificate.t list * X509.Private_key.t, [> error ]) result
