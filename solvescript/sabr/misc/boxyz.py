#!/usr/bin/env -S python3 -W ignore
# -*- coding: utf-8 -*-
from pwn import *
import claripy
import sys

PROG = './boxyz'
HOST = '13.36.37.184'
PORT = 1337

LOCAL = False
if 'local' in sys.argv:
        LOCAL = True

for i in range(1, len(sys.argv)):
        arg = sys.argv[i]
        if arg != 'local':
                if i == 1:
                        HOST = sys.argv[i]
                if i == 2:
                        PORT = int(sys.argv[i])

if LOCAL:
        io = process(PROG)
else:
        io = remote(HOST, PORT)


def sendin(val):

        if len(val) > 0:
                io.clean()
                io.send(val)

        io.recvuntil(b'values:\x1b[0m')
        x = io.recvuntil('│')[:-4]
        x = x.decode("utf-8").strip().split(' ')
        values = []
        for j in range(len(x)):
                num = x[j].strip()
                if len(num) > 0:
                        values.append(int(num))

        io.recvuntil(b'target:\x1b[0m')
        target = io.recvuntil('│')[:-4]
        target = int(target.decode('utf-8').strip().split(' ')[0])
        io.clean()

        return (target, values)


def diff(start, values):

        ret = []
        for i in range(len(start)):
                ret.append(values[i] - start[i])

        return ret


def solve(target, table, start):

        s = claripy.Solver()

        x1 = claripy.BVS('x1', 8)
        x2 = claripy.BVS('x2', 8)
        x3 = claripy.BVS('x3', 8)
        x4 = claripy.BVS('x4', 8)
        x5 = claripy.BVS('x5', 8)
        x6 = claripy.BVS('x6', 8)
        x7 = claripy.BVS('x7', 8)
        x8 = claripy.BVS('x8', 8)
        x9 = claripy.BVS('x9', 8)

        L = [0, 0, 0, 0, 0, 0, 0, 0, 0]
        for i in range(0, 9):
                L[i] = ((x1 * table[0][i]) +
                        (x2 * table[1][i]) +
                        (x3 * table[2][i]) +
                        (x4 * table[3][i]) +
                        (x5 * table[4][i]) +
                        (x6 * table[5][i]) +
                        (x7 * table[6][i]) +
                        (x8 * table[7][i]) +
                        (x9 * table[8][i]))

        s.add(claripy.And(
                L[0] == target-start[0],
                L[1] == target-start[1],
                L[2] == target-start[2],
                L[3] == target-start[3],
                L[4] == target-start[4],
                L[5] == target-start[5],
                L[6] == target-start[6],
                L[7] == target-start[7],
                L[8] == target-start[8],
                L[8]+start[8] == target
        ))

        s.add(claripy.And(x1 <= 45, x2 <= 45, x3 <= 45, x4 <= 45, x5 <= 45, x6 <= 45, x7 <= 45, x8 <= 45, x9 <= 45))
        s.add(claripy.And(x1 >= 0, x2 >= 0, x3 >= 0, x4 >= 0, x5 >= 0, x6 >= 0, x7 >= 0, x8 >= 0, x9 >= 0))

        a1 = s.eval(x1, 1)[0]
        a2 = s.eval(x2, 1)[0]
        a3 = s.eval(x3, 1)[0]
        a4 = s.eval(x4, 1)[0]
        a5 = s.eval(x5, 1)[0]
        a6 = s.eval(x6, 1)[0]
        a7 = s.eval(x7, 1)[0]
        a8 = s.eval(x8, 1)[0]
        a9 = s.eval(x9, 1)[0]

        result = '1'*a1 + '2'*a2 + '3'*a3 + '4'*a4 + '5'*a5 + '6'*a6 + '7'*a7 + '8'*a8 + '9'*a9
        return result


for i in range(64):

        io.recvuntil(b'round ')
        n = int(io.recvuntil(b'/')[:-1])
        io.recvline()

        log.info('round: %d' % n)
        io.recvline()

        table = []
        target, start = sendin('')

        for c in range(1, 10):

                _, values = sendin(str(c))

                diffs = diff(start, values)
                table.append(diffs)

                #io.interactive()
                sendin('0')

        result = solve(target, table, start)
        io.sendline(result)

        log.success('input: %s' % result)


io.recvuntil(b'YOU DID IT')
io.recvline()
log.success('flag: %s' % io.recvline().strip())
