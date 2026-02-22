val make :
     string
  -> seed:string
  -> ( X509.Certificate.t * X509.Private_key.t * X509.Authenticator.t
     , [> `Msg of string ] )
     result
