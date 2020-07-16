#! /bin/bash

ls | wc -l
ps aux
ls > /tmp/ls.log
cat /tmp/ls.log
/bin/echo foo > /tmp/foo
grep foo /tmp/foo
