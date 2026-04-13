#!/bin/bash

[ ! -d "vendors" ] && mkdir vendors
[ ! -d "vendors/bstr" ] && opam source bstr --dir vendors/bstr
[ ! -d "vendors/digestif" ] && opam source digestif --dir vendors/digestif
[ ! -d "vendors/gmp" ] && opam source gmp --dir vendors/gmp
[ ! -d "vendors/kdf" ] && opam source kdf --dir vendors/kdf
[ ! -d "vendors/mirage-crypto-rng-mkernel" ] && opam source mirage-crypto-rng-mkernel --dir vendors/mirage-crypto-rng-mkernel
[ ! -d "vendors/mkernel" ] && opam source mkernel --dir vendors/mkernel
[ ! -d "vendors/mnet" ] && opam source mnet --dir vendors/mnet
[ ! -d "vendors/utcp" ] && opam source utcp --dir vendors/utcp
[ ! -d "vendors/flux" ] && opam source flux --dir vendors/flux
[ ! -d "vendors/tls" ] && opam source tls --dir vendors/tls
[ ! -d "vendors/x509" ] && opam source x509 --dir vendors/x509
[ ! -d "vendors/ca-certs-nss" ] && opam source ca-certs-nss --dir vendors/ca-certs-nss
[ ! -d "vendors/zarith" ] && opam source zarith --dir vendors/zarith
[ ! -d "vendors/msendmail" ] && opam source msendmail --dir vendors/msendmail
[ ! -d "vendors/mrmime" ] && opam source mrmime --dir vendors/mrmime
[ ! -d "vendors/prettym" ] && opam source prettym --dir vendors/prettym
[ ! -d "vendors/mirage-ptime" ] && opam source mirage-ptime --dir vendors/mirage-ptime
[ ! -d "vendors/cattery" ] && opam source cattery --dir vendors/cattery
[ ! -d "vendors/dmarc" ] && opam source dmarc --dir vendors/dmarc
[ ! -d "vendors/dkim" ] && opam source dkim --dir vendors/dkim
[ ! -d "vendors/uspf" ] && opam source uspf --dir vendors/uspf
[ ! -d "vendors/arc" ] && opam source arc --dir vendors/arc
[ ! -d "vendors/dns-tsig" ] && opam source dns-tsig --dir vendors/dns-tsig
[ ! -d "vendors/mfat" ] && opam source mfat --dir vendors/mfat
[ ! -d "vendors/cachet" ] && opam source cachet --dir vendors/cachet
