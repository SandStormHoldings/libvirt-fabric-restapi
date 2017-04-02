#!/usr/bin/python
# macgen.py script to generate a MAC address for virtualized guests
#
from __future__ import print_function
from builtins import map
from builtins import range
import random
import sys
import re
import hashlib
from config import HOSTS,HOST_IDX, main_network
#


def randomMAC(host,counters):
    if host not in counters: counters[host]=0

    respl = re.compile('(..)')
    hsh = hashlib.md5(host.encode('utf-8'))
    host_suffix = hsh.hexdigest()[0:4]
    mac = [ 0x00, 0x16, 0x3e,
        random.randint(0x00, 0x7f),
        random.randint(0x00, 0xff),
        random.randint(0x00, 0xff) ]
    mapped = list(map(lambda x: "%02x" % x, mac))[0:3]

    host_suffix_spl = (respl.findall(host_suffix))

    rt= ':'.join(mapped+['%02x'%counters[host]]+host_suffix_spl)
    counters[host]+=1
    return rt

def genmacs(only_host=None):
    rt=''
    ipcounter=0
    dom_counters = {}
    for host,ip in list(HOSTS.items()):
        if only_host and host!=only_host: continue
        rt+='# %s (%s)\n'%(host,ip)

        for i in range(10,255):
            vhostaddr = '%s.%s.%s'%(main_network, HOST_IDX[host],i)
            rt+= "host virt-%s-%s { hardware ethernet %s; fixed-address %s; }\n"%(host,ipcounter,randomMAC(host,dom_counters),vhostaddr)
            ipcounter+=1
        rt+="\n"
    return rt

if 'range' in sys.argv:
    print(genmacs())
elif __name__=='__main__':
    print(randomMAC())
