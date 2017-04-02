#!/usr/bin/env python                                                                                                                                  
from __future__ import print_function
import sys
import re
import os
fns = ([os.path.join(os.path.dirname(__file__),'conf_repo/keydir',fn) for fn in os.listdir(os.path.join(os.path.dirname(__file__),'conf_repo/keydir')) if fn.endswith('.pub')])
fns.append(os.path.join(os.path.dirname(__file__),'conf_repo/recognized_authorized_keys.txt'))
fns.append(os.path.join(os.path.dirname(__file__),'conf_repo/recognized_authorized_keys-jumphost.txt'))

for ln in sys.stdin:
    for fn in fns:
        for rln in open(fn,'r').read().split("\n"):
            if not rln: continue
            rln = rln.strip()
            try:
                (proto,key,name) = rln.split(" ")
            except:
                print('cannot split "',rln,"'")
                raise
            ln = re.sub(re.escape(" ".join([proto,key]))+'.*$',
                        name,
                        ln)
    lns = ln.strip()
    if lns: print(lns)
