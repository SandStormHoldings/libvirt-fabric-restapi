#!/usr/bin/env python

import md5
import sys

def repeatable_random(seed,lim):
    hash = seed
    i=0
    while i<lim:
        i+=1
        hash = md5.md5(hash).digest()
        for c in hash:
            yield ord(c)

def test(seed):
    for k in repeatable_random(sys.argv[1], int(sys.argv[2])):
        print k,
test(sys.argv[1])
