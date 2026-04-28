#!/bin/sh

solo5-hvt --net:service=tap1 -- _build/solo5/pagejaune.exe --ipv4=10.0.0.3/24 --ipv4-gateway=10.0.0.1 -vvv --color=always --domain bar.local \
  --dnssec --qname-minimisation
