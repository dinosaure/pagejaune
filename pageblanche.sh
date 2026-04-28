#!/bin/sh

PIN=$(dig TLSA _853._tcp.bar.local @10.0.0.3 +short | cut -d ' ' -f4- | tr -d ' ')
echo $PIN
solo5-hvt --net:service=tap0 --block:lst=lst.img -- _build/solo5/pageblanche.exe --ipv4=10.0.0.2/24 --ipv4-gateway=10.0.0.1 -vvv --color=always --domain foo.local --pagejaune "10.0.0.3!bar.local!$PIN"
