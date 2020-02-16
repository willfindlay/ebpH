#! /usr/bin/env sh
cat /var/log/ebpH/ebph.log | sed "s/.*DEBUG\(.*\)/\1/" | grep "Mismatch" | uniq -c | awk '$1 > 1 {print}'
