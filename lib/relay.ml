

let accept ?encoder ?decoder ?queue ~info flow =
  let ctx = Sendmail_with_starttls.Context_with_tls.make ?encoder ?decoder ?queue () in
  let t = SMTP.m_relay_init ctx info in
  let 
