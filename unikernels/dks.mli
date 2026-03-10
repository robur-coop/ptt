type error =
  [ `Msg of string
  | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
  | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t
  | Dns_tsig.s
  | Dns_tsig.e
  | Dns.Packet.mismatch ]

val pp_error : error Fmt.t

val verify :
  Mnet_dns.t -> 'a Dkim.t -> Dkim.domain_key -> (bool, [> error ]) result

val domain_keys :
     Mnet.TCP.state
  -> Ipaddr.t * int
  -> _ Domain_name.t * Dns.Dnskey.t
  -> _ Domain_name.t
  -> (([ `raw ] Domain_name.t * Dkim.domain_key) list, [> error ]) result

val update :
     Mnet.TCP.state
  -> Ipaddr.t * int
  -> _ Domain_name.t * Dns.Dnskey.t
  -> 'a Dkim.t
  -> Dkim.domain_key
  -> (unit, [> error ]) result

type selector = Selector : { prj: prj; inj: inj; raw: string } -> selector
and prj = (int -> string, Format.formatter, unit, string) format4
and inj = (int -> int, Scanf.Scanning.scanbuf, (int -> int) -> int, int) format4

val lint_and_sort :
     selector
  -> ('a Domain_name.t * Dkim.domain_key) list
  -> (Ptime.t * 'a Domain_name.t * Dkim.domain_key) list

val selector : string -> (selector, [> `Msg of string ]) result
