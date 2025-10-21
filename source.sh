#!/bin/bash

opam pin add -yn --ignore-pin-depends git+https://github.com/robur-coop/utcp.git
opam pin add -yn --ignore-pin-depends git+https://git.robur.coop/robur/mnet.git#with-tls
opam pin add -yn --ignore-pin-depends git+https://git.robur.coop/robur/mkernel.git
opam pin add -yn --ignore-pin-depends git+https://github.com/dinosaure/mirage-crypto.git#miou-solo5
opam pin add -yn --ignore-pin-depends git+https://github.com/mirage/mirage-ptime.git#fix-compilation-without-solo5-context

[ ! -d "vendors" ] && mkdir vendors
[ ! -d "vendors/bstr" ] && opam source bstr --dir vendors/bstr
[ ! -d "vendors/digestif" ] && opam source digestif --dir vendors/digestif
[ ! -d "vendors/gmp" ] && opam source gmp --dir vendors/gmp
[ ! -d "vendors/kdf" ] && opam source kdf --dir vendors/kdf
[ ! -d "vendors/mirage-crypto-rng-mkernel" ] && opam source mirage-crypto-rng-mkernel --dir vendors/mirage-crypto-rng-mkernel
[ ! -d "vendors/mkernel" ] && opam source mkernel --dir vendors/mkernel
[ ! -d "vendors/mnet" ] && opam source mnet --dir vendors/mnet
[ ! -d "vendors/x509" ] && opam source x509 --dir vendors/x509
[ ! -d "vendors/dns-server" ] && opam source dns-server --dir vendors/dns-server
[ ! -d "vendors/tls" ] && opam source tls --dir vendors/tls
[ ! -d "vendors/ca-certs-nss" ] && opam source ca-certs-nss --dir vendors/ca-certs-nss
[ ! -d "vendors/mirage-ptime" ] && opam source mirage-ptime --dir vendors/mirage-ptime
