type 'fs t

type 'fs action = {
    get: 'fs -> Mrmime.MessageID.t -> string
  ; add: 'fs -> Mrmime.MessageID.t -> string -> unit
  ; rem: 'fs -> Mrmime.MessageID.t -> unit
}

val create :
     info:Facteur.info
  -> ?store:('fs t -> unit)
  -> Facteur.t
  -> Ptt.resolver
  -> 'fs
  -> 'fs action
  -> Bounces.t
  -> 'fs t

val json :
     info:Facteur.info
  -> ?store:('fs t -> unit)
  -> Facteur.t
  -> Ptt.resolver
  -> 'fs
  -> 'fs action
  -> Bounces.t
  -> 'fs t Jsont.t

val add_new_failure :
     'fs t
  -> counter:int
  -> from:Colombe.Path.t
  -> Colombe.Path.t
  -> string
  -> unit

val launch : 'fs t -> unit
