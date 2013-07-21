#!/bin/bash

./errgen --port 5678 --ctl-port 5679 --address localhost --uuid timeout10 --timeout 10&
./errgen --port 5678 --ctl-port 5679 --address localhost --uuid timeout2 --timeout 2&
./monitor --port 5678 --ctl-port 5679 --action kill --timeout 20 --err-threshold 5&

watch tail -40 /var/log/syslog

