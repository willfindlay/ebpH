#! /usr/bin/env sh

# Read /var/log/ebpH/newseq.log and strip the beginning formatting such that only
# the important parts remain. We can then pipe into something like uniq -D to look
# for duplicate new sequences.

awk '/INFO:/ {for (i=10; i<=NF; i++){printf "%s ", $i} printf "\n"}' /var/log/ebpH/newseq.log
