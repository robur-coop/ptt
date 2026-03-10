type locals = [ `All | `Postmaster | `Some of Emile.local list ]

type destination = {
    domain: [ `Ipaddr of Ipaddr.t | `Domain of [ `host ] Domain_name.t ]
  ; locals: locals
}

val pp : destination Fmt.t

val to_recipients :
  domain:Colombe.Domain.t -> Colombe.Forward_path.t list -> destination list
