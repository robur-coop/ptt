let src = Logs.Src.create "ptt.aggregate"

module Log = (val Logs.src_log src)
module By_domain = Domain_name.Host_map
module By_ipaddr = Ipaddr.Map

let postmaster = [ `Atom "Postmaster" ]
let equal_local = Emile.equal_local ~case_sensitive:true

type locals = [ `All | `Postmaster | `Some of Emile.local list ]

type destination = {
    domain: [ `Ipaddr of Ipaddr.t | `Domain of [ `host ] Domain_name.t ]
  ; locals: locals
}

let pp_locals ppf = function
  | `All -> Fmt.string ppf "all"
  | `Postmaster -> Fmt.string ppf "postmaster"
  | `Some locals ->
      Fmt.pf ppf "%a" Fmt.(list ~sep:(any ",") Emile.pp_local) locals

let pp_domain ppf = function
  | `Ipaddr ipaddr -> Ipaddr.pp ppf ipaddr
  | `Domain domain_name -> Domain_name.pp ppf domain_name

let pp ppf { domain; locals } =
  Fmt.pf ppf "@@%a:%a" pp_domain domain pp_locals locals

let of_strings sstr =
  let open Result.Syntax in
  let* domain_name = Domain_name.of_strings sstr in
  Domain_name.host domain_name

let add_by_domain ~domain elt by_domains =
  match (elt, By_domain.find_opt domain by_domains) with
  | `All, _ -> By_domain.add domain `All by_domains
  | _, Some `All | `Postmaster, Some `Postmaster -> by_domains
  | `Postmaster, Some (`Some vs) ->
      if List.exists (equal_local postmaster) vs then by_domains
      else By_domain.add domain (`Some (postmaster :: vs)) by_domains
  | `Some v, Some (`Some vs) ->
      if List.exists (equal_local v) vs then by_domains
      else By_domain.add domain (`Some (v :: vs)) by_domains
  | `Some v, Some `Postmaster ->
      By_domain.add domain (`Some [ v; postmaster ]) by_domains
  | `Postmaster, None -> By_domain.add domain `Postmaster by_domains
  | `Some v, None -> By_domain.add domain (`Some [ v ]) by_domains

let add_by_ipaddr ipaddr elt by_ipaddrs =
  match (elt, By_ipaddr.find_opt ipaddr by_ipaddrs) with
  | `All, _ -> By_ipaddr.add ipaddr `All by_ipaddrs
  | _, Some `All -> by_ipaddrs
  | `Some v, Some (`Some vs) ->
      if List.exists (equal_local v) vs then by_ipaddrs
      else By_ipaddr.add ipaddr (`Some (v :: vs)) by_ipaddrs
  | `Some v, None -> By_ipaddr.add ipaddr (`Some [ v ]) by_ipaddrs

let aggregate_by_domains ~domain =
  let open Colombe in
  let open Forward_path in
  let fold (by_domains, by_ipaddrs) = function
    | Postmaster ->
        begin match domain with
        | Colombe.Domain.(IPv4 _ | IPv6 _ | Extension _) ->
            Log.err (fun m ->
                m
                  "The SMTP server domain is not a domain-name, impossible to \
                   add the postmaster as a recipient");
            (by_domains, by_ipaddrs)
        | Colombe.Domain.Domain ds ->
            begin match of_strings ds with
            | Ok domain ->
                (add_by_domain ~domain `Postmaster by_domains, by_ipaddrs)
            | Error (`Msg _) ->
                Log.err (fun m ->
                    m
                      "Invalid SMTP server domain, impossible to add the \
                       postmaster as a recipient");
                (by_domains, by_ipaddrs)
            end
        end
    | Forward_path { Path.domain= Domain.Domain v; Path.local; _ } as recipient
      ->
        begin match of_strings v with
        | Ok domain ->
            let local = Colombe_emile.of_local local in
            (add_by_domain ~domain (`Some local) by_domains, by_ipaddrs)
        | Error (`Msg msg) ->
            Log.warn (fun m ->
                m "Invalid domain for %a, ignore it: %s" Forward_path.pp
                  recipient msg);
            (by_domains, by_ipaddrs)
        end
    | Domain (Domain.Domain v) as recipient ->
        begin match of_strings v with
        | Ok domain -> (add_by_domain ~domain `All by_domains, by_ipaddrs)
        | Error (`Msg msg) ->
            Log.warn (fun m ->
                m "Invalid domain for %a, ignore it: %s" Forward_path.pp
                  recipient msg);
            (by_domains, by_ipaddrs)
        end
    | Domain (Domain.IPv4 v4) ->
        (by_domains, add_by_ipaddr (Ipaddr.V4 v4) `All by_ipaddrs)
    | Domain (Domain.IPv6 v6) ->
        (by_domains, add_by_ipaddr (Ipaddr.V6 v6) `All by_ipaddrs)
    | Forward_path { Path.domain= Domain.IPv4 v4; Path.local; _ } ->
        let local = Colombe_emile.of_local local in
        (by_domains, add_by_ipaddr (Ipaddr.V4 v4) (`Some local) by_ipaddrs)
    | Forward_path { Path.domain= Domain.IPv6 v6; Path.local; _ } ->
        let local = Colombe_emile.of_local local in
        (by_domains, add_by_ipaddr (Ipaddr.V6 v6) (`Some local) by_ipaddrs)
    | ( Domain (Domain.Extension _)
      | Forward_path { Path.domain= Domain.Extension _; _ } ) as recipient ->
        Log.warn (fun m ->
            m "We don't support domain extension, ignore %a" Forward_path.pp
              recipient);
        (by_domains, by_ipaddrs)
  in
  List.fold_left fold (By_domain.empty, By_ipaddr.empty)

let to_recipients ~domain recipients =
  let by_domains, by_ipaddrs = aggregate_by_domains ~domain recipients in
  let fn (domain, locals) = { domain= `Domain domain; locals } in
  let by_domains = List.map fn (By_domain.bindings by_domains) in
  let fn (ipaddr, locals) = { domain= `Ipaddr ipaddr; locals:> locals } in
  let by_ipaddrs = List.map fn (By_ipaddr.bindings by_ipaddrs) in
  List.rev_append by_domains by_ipaddrs
