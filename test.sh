#!/bin/bash

./errgen -p 5678 -a localhost -t 10&
./errgen -p 5678 -a localhost -t 3&
./monitor -p 5678 -a kill -t 20 -e 5&

