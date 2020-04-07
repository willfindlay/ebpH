#! /usr/bin/env bash

LOGFILE=/var/log/ebpH/ebph.log
DURATION=$(( 30 * 1000 ))

send_notification() {
    read PID COMM KEY SYSCALLS
    notify-send -t $DURATION -u critical -c ebpH "ebpH detected anomalies in PID $PID" "($COMM $KEY): $SYSCALLS"
}

tail -f -n 0 "$LOGFILE" |
    while read line; do
        x=`echo $line |
            cut -d' ' -f'5-' |
            grep -i '^anomalies' |
            perl -pe 's/Anomalies in PID (\d+) \((\S+) (\S+)\): (.*)/\1 \2 \3 \4/p'`
        [[ ! -z "$x" ]] && echo "$x" | send_notification
    done
