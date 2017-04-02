#!/usr/bin/env python
"""
tabular display of the running hypervisors in the console.
"""
__author__='Guy Romm'

from __future__ import print_function
from builtins import str
from builtins import object
try:
    from fabric.api import *
    from fabric.contrib.files import exists,append,comment,upload_template
    from prettytable import PrettyTable
except ImportError:
    print('#'*80)
    print('YOU NEED TO pip install -r requirements.txt')
    print('#'*80)
    raise
import os
import sys
import re
import fabfile
import config as cfg
# import set_settings


class ParallelCommands(object):
    def __init__(self, **args):
        self.hosts = args['hosts']
        self.command = args['command']

    @parallel(pool_size=10) # Run on as many as 10 hosts at once
    def parallel_exec(self):
        return run(self.command)

    def capture(self):
        with settings(hide('running', 'commands', 'stdout', 'stderr')):
            stdout = execute(self.parallel_exec, hosts=self.hosts)
        return stdout
m2re = (re.compile('(buffers/cache|Mem):([^0-9]+)([0-9]+)([^0-9]+)([0-9]+)([^0-9]+)([0-9]+)([^0-9]+)([0-9]+)([^0-9]+)([0-9]+)([^0-9]+)([0-9]+)'),13,'mem free')
dre =  (re.compile('([0-9]+)([ ]+)([0-9]+)% /$'),1,'disk available')
mre =  (re.compile('buffers/cache:([^0-9]+)([0-9]+)([^0-9]+)([0-9]+)$'),4,'mem free')
lre =  (re.compile('load average: ([0-9\.]+), ([0-9\.]+), ([0-9\.]+)$'),3,'load 15')
ngre = (re.compile('nodegroups: (.*)$'),1,'nodegroups')
rnre = (re.compile('(^[0-9]+) running nodes'),1,'running nodes')
tnre = (re.compile('(^[0-9]+) total nodes'),1,'total nodes')
tests = [dre,mre,m2re,lre,rnre,tnre,ngre]
commands = ["free -m",
            "df -m",
            "uptime",
            """virsh -q list  | wc -l | awk '{print $1,"running nodes"}'""",
            """virsh -q list --all  | wc -l | awk '{print $1,"total nodes"}'""",
            """virsh -q list --all | awk '{print $2}' | cut -f1 -d'-' | sort | uniq -c | awk '{print $2"("$1")"}' | sed ':a;N;$!ba;s/\\n/,/g' | awk '{print "nodegroups: "$1}'"""
            ]
head = ['host','mem free','load 15','disk available','running nodes','total nodes','nodegroups','notes','unpriv']
#print(commands[-1]) ; sys.exit(1)
def parse_output(hop,h):

    rt=[]
    #print '%s returned %s'%(h,hop)
    for ln in hop.split('\n'):
        ln=ln.strip()
        mres = [(t[2],t[0].search(ln),t[1]) for t in tests]
        mres = [x for x in mres if x[1]]
        rt+=mres
    #raise Exception(env.host_string,rt)
    rt = [(i[0],i[1].group(i[2])) for i in rt if i]
    rt.append(['notes',cfg.NOTES.get(h,'--')])
    rt.append(['host',h])
    rt.append(['unpriv',h in cfg.LOWERED_PRIVILEGES and 'Y' or 'N'])
    return rt

if __name__=='__main__':
    #set_settings()
    instance = ParallelCommands(hosts=len(sys.argv)>1 and [sys.argv[1]] or env.roledefs['kvm'], command="; ".join(commands))
    output = instance.capture()
    hres={}
    for h,hop in list(output.items()): hres[h]=parse_output(hop,h)

    pt = PrettyTable(head)

    for h,hvals in list(hres.items()):
        rw = dict(hvals) #dict(hvals+[('host',h),('notes',cfg.NOTES.get(h,'--'))])
        pt.add_row([rw.get(i,'--') for i in head])
    print("\n".join([(ln.startswith('+') and '|'+ln[1:] or ln) for ln in str(pt).split("\n")[1:-1]]))
            
