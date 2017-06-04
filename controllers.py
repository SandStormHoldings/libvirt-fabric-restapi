#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
'''
REST API controllers file
'''
__author__='Guy Romm'

from future import standard_library
standard_library.install_aliases()
from builtins import str
import sys
import datetime
import time
import traceback
from functools import wraps
from noodles.http import Response,XResponse,Error403
from fabric.api import *
from fabfile import (_lst,create_node,destroy,reboot,undefine,start,migrate,
                     get_dns, add_dns, del_dns, enlarge_lvm, get_tmux_sessions,
                     node_network_info, kill_tmux_session,node_auth,list_openvpn,
                     openvpn_ipp,openvpn_all as openvpn_all_worker,
                     openvpn_status as openvpn_status_worker, append_openvpn, getmem)
from config import AUTH_DB_FILE,IMAGES,DEFAULT_RAM,DEFAULT_VCPU,HOSTS,DNS_HOST,OVPN_HOST
from noodles.templates import render_to
from noodles.digest.decorators import httpdigest as httpdigest
import re
import json
from subprocess import getstatusoutput as gso
import random
import os
from gevent.lock import BoundedSemaphore

def C(attr):
    return json.load(open(AUTH_DB_FILE,'r'))[attr]


def usergroups(username):
    #print('going through groups ',C('groups').items(),' for user ',username)
    return [gn for gn,u in list(C('groups').items()) if username in u]

def l(msg):
    sys.stderr.write(msg+"\n")

def prefix_re(username):
    ug = usergroups(username)
    conc = '^('+'|'.join([re.escape(un) for un in ug])+')'
    rt = re.compile(conc)
    #raise Exception(conc,rt.search('tasks1'))
    l(" ".join([username,'groups are',str(ug)]))
    return rt


def execute_cli(cmd,host,**kwargs):
    kwa = ','.join(['='.join([k,v]) for k,v in list(kwargs.items())])
    fcmd = '~/bin/fab -H %s %s:%s'%(host,cmd,kwa)
    print(fcmd)
    st,op = gso(fcmd)
    return {'code':st,'result':op}


mre = re.compile('Digest username="([^"]+)"')
def getuser(request):
    mres = mre.search(request.headers.get('Authorization'))
    return mres.group(1)


def pre_from_req(req):
    return prefix_re(getuser(req))

from functools import wraps

sem = BoundedSemaphore(1)
def lck(f):
     @wraps(f)
     def wrapper(*args, **kwds):
         print('about to obtain lock in order to execute %s(%s,%s)'%(f,args,kwds))
         sem.acquire(blocking=True,timeout=120)

         rt= f(*args,**kwds)

         print('command ran - unlocking')
         sem.release()

         print('unlocked and closed.')
         return rt
     return wrapper

@render_to('/index.html')
@lck 
@httpdigest
def index(request):
    return {}


def _host():
    from hosts import commands
    return run("; ".join(commands))

@lck 
@httpdigest
def hosts(request):
    from hosts import commands,tests,parse_output
    output = execute(_host,roles=['kvm'])
    hres = {}
    for h,hop in list(output.items()):
        hres[h]=parse_output(hop,h)
        hres[h].append(['ip',HOSTS[h]])
    for h in hres:
        hres[h]=dict(hres[h])
    return XResponse(hres)

@lck 
@httpdigest
def slp(request,seconds):
    time.sleep(int(seconds))
    return XResponse({'seconds':seconds})

@lck 
@httpdigest
def migrate_node(request,host,node):
    try:
        pre = pre_from_req(request)
        assert pre.search(node),"no permissions to access %s for %s"%(node,getuser(req))

        dst_host = host
        dst_node = node
        src_host = request.params.get('source_host')
        assert src_host

        with settings(host_string=src_host):
            rt = migrate(node,dst_host,src_host,nocopy=bool(request.params.get('nocopy',False)))
        return XResponse({'migrated':rt})
    except Exception as e:
        from sys import exc_info
        from traceback import format_tb
        exc_type, exc_value, exc_traceback = exc_info()
        return XResponse({'error': e,
                          'exception': format_tb(exc_traceback)})

@lck 
@httpdigest
def delete_node(request,host,node):
    pre = pre_from_req(request)
    assert pre.search(node),"no permissions to access %s"%node

    try:
        l1 = execute_cli('destroy',node=node,host=host)
        l = execute_cli('undefine',node=node,host=host,target=host)
        return XResponse({'result':l})
    except Exception as e:
        return XResponse({'error':e})


@lck 
@httpdigest
def host_auth_list(request,host,node):
    pre = pre_from_req(request)
    assert pre.search(node),"no permissions to access %s (%s)"%(node,pre)

    l = execute(_lst,network_info=False,display=False,al=True,host=host,prefix_re=re.compile('^'+re.escape(node)+'$'))
    ni = host in l and l[host]
    ni = node in ni and ni[node]
    node_ip = ni and 'virt_ip' in ni and ni['virt_ip']
    if not node_ip:
        return XResponse({'error':'could not locate %s -> %s -> virt_ip'%(host,node)})
    op = execute(run,'cat ~/.ssh/authorized_keys',host=node_ip)[node_ip]
    ak = [i.strip() for i in op.split("\n")]
    return XResponse({'result':ak})

@lck 
@httpdigest
def host_auth_add(request,host,node):
    pre = pre_from_req(request)
    assert pre.search(node),"no permissions to access %s"%node

    pubkey = request.params.get('pubkey')
    li = execute(_lst,network_info=False,display=False,al=True,host=host,prefix_re=re.compile('^'+re.escape(node)+'$'))
    node_ip = li[host][node]['virt_ip']
    res = execute(node_auth,pubkey,host=node_ip)[node_ip]
    return XResponse({'result':res,'host':host,'node':node,'node_ip':node_ip})

@lck
@httpdigest
def openvpn_all(request):
    pre = pre_from_req(request)
    if not pre.search(OVPN_HOST): return Error403("no permissions to access %s"%OVPN_HOST)
    return XResponse({'result':execute(openvpn_all_worker,host=OVPN_HOST)})

@lck
@httpdigest
def openvpn_status(request):
    pre = pre_from_req(request)
    if not pre.search(OVPN_HOST): return Error403("no permissions to access %s"%OVPN_HOST)
    return XResponse({'result':execute(openvpn_status_worker,host=OVPN_HOST)})

@lck 
@httpdigest
def openvpn_list(request):
    pre = pre_from_req(request)
    if not pre.search(OVPN_HOST): return Error403("no permissions to access %s"%OVPN_HOST)
    return XResponse({'result':execute(list_openvpn,host=OVPN_HOST)})

@lck
@httpdigest
def openvpn_ips(request):
    pre = pre_from_req(request)
    if not pre.search(OVPN_HOST): return Error403("no permissions to access %s"%OVPN_HOST)
    return XResponse({'result':execute(openvpn_ipp,host=OVPN_HOST)})
    
@lck 
@httpdigest
def openvpn_add(request):
    r = request
    pre = pre_from_req(r)
    user = getuser(r)
    if not pre.search(OVPN_HOST): return Error403("no permissions to access %s"%OVPN_HOST)

    un = r.params.get('key')
    assert len(un),"key parameter missing"
    em = r.params.get('email')
    assert em and '@' in em,"%s not a valid email"%em
    comment = r.params.get('comment')
    comment = comment and '%s by %s'%(comment,user) or 'by %s'%user
    rt = append_openvpn(un,em,comment)
    return XResponse({'result':'ok','apnd':rt})

@lck 
@httpdigest
def update_node(request,host,node):
    pre = pre_from_req(request)
    ug = usergroups(getuser(request))
    assert pre.search(node),"no permissions (%s) to access %s"%(ug,node)
    #running,shut off,reboot
    state = request.params.get('state')
    try:
        if state=='shut off':
            rt=execute_cli('destroy',node=node,host=host)
        elif state=='reboot':
            rt=execute_cli('reboot',node=node,host=host)
        elif state=='running':
            rt=execute_cli('start',node=node,host=host)
        elif state=='resumed':
            rt=execute_cli('resume',node=node,host=host)
        else:
            raise Exception('unknown command')
        return XResponse({'result':rt})
    except Exception as e:
        return XResponse({'error':str(e)})


@lck 
@httpdigest
def node(request,host,node):
    pre = pre_from_req(request)
    assert pre.search(node),"no permissions to access %s"%node

    l = execute(_lst,network_info=False,display=False,al=True,host=host,prefix_re=re.compile('^'+re.escape(node)+'$'))
    return XResponse(l)


@lck 
@httpdigest
def new_node(request,host=None):
    username = getuser(request)
    pre = pre_from_req(request)
    mygroups = usergroups(username)

    args = {'name':request.params.get('name'),
            'image':request.params.get('image'),
            'group':request.params.get('group'),
            'host':request.params.get('host',host),
            'memory':request.params.get('memory',DEFAULT_RAM),
            'vcpu':request.params.get('vcpu',DEFAULT_VCPU),
            'pubkey':request.params.get('pubkey'),
            'simulate':request.params.get('simulate') and request.params.get('simulate') or False}

    assert args.get('name')
    imgn = args.get('image')
    imgkeys=list(IMAGES.keys())
    if imgn not in imgkeys: raise Exception("%s not in %s"%(imgn,imgkeys))
    assert args.get('group') in mygroups,"group %s is not in my allowed groups %s"%(args.get('group'),mygroups)
    assert args.get('host') in list(HOSTS.keys()),"host %s not found in %s"%(args.get('host'),list(HOSTS.keys()))
    try:
        res = execute(create_node,
                      args['group']+'-'+args['name'],
                      imgn,
                      memory=args['memory'],
                      vcpu=args['vcpu'],
                      host=args['host'],
                      simulate=args['simulate'])
    except Exception as e:
        traceback.print_exc()
        return XResponse({'error':str(e)})
    print('CREATED',res)
    return XResponse({'created':res})


@lck 
@httpdigest
def nodes(request,host=None):
    username = getuser(request)
    pre = pre_from_req(request)

    mygroups = usergroups(username)
    if request.params.get('exc'): raise Exception('test exc')
    if host:
        l = execute(_lst,network_info=False,display=False,host=host,prefix_re=pre,al=True)
    else:
        l = execute(_lst,network_info=False,display=False,roles=['kvm'],prefix_re=pre,al=True)

    return XResponse(l)


@lck 
@httpdigest
def images(request):
    return XResponse({'images':IMAGES})


@lck 
@httpdigest
def groups(request):
    username = getuser(request)
    groups = usergroups(username)
    return XResponse({'groups':groups})

@lck 
@httpdigest
def dns(request):
    with settings(host_string=DNS_HOST):
        records = get_dns()
        return XResponse({'result': {'code': 0, 'result': records}})

@lck 
@httpdigest
def new_dns_record(request, domain):
    assert 'addr' in request.params
    try:
        with settings(host_string=DNS_HOST):
            addr = request.params.get('addr')
            res = execute(add_dns, domain, addr)
    except Exception as e:
        traceback.print_exc()
        return XResponse({'error':str(e)})
    return XResponse({'result': {'code': 0, 'result': res}})

@lck 
@httpdigest
def del_dns_record(request, domain):
    try:
        with settings(host_string=DNS_HOST):
            res = execute(del_dns, domain)
    except Exception as e:
        traceback.print_exc()
        return XResponse({'error':str(e)})
    return XResponse({'result': {'code': 0, 'result': res}})

@lck 
@httpdigest
def enlarge_disk(request, host, node):
    # fixme: return error if node's disk is not based on large image
    pre = pre_from_req(request)
    assert pre.search(node), "no permissions to access %s" % node
    size = request.params.get('size', '50G')
    print('going to resize %s@%s to %s'%(host,node,size))
    try:
        rt = execute_cli('enlarge_lvm', target=node, host=host, new_size=size)
    except Exception as e:
        traceback.print_exc()
        return XResponse({'error':str(e)})
    return XResponse({'result': rt})

@lck 
@httpdigest
def sessions(request):
    machines = execute(_lst, network_info=False, display=False, roles=['kvm'],
                       prefix_re=re.compile('^jenkins'), al=True)

    guests = {guest['virt_ip']: (guest['name'], guest['host'])
              for m in list(machines.values()) for guest in list(m.values()) if guest['state']=='running'}

    with settings(parallel=True, hosts=list(guests.keys())):
        guest_results = execute(get_tmux_sessions)

    result = {}
    for guest_ip, guest_data in guest_results.items():
        name, host = guests[guest_ip]
        result[name] = dict(host=host, **guest_data)
    return XResponse(result)

@lck 
@httpdigest
def kill_session(request, host, node, name):
    ourhost = {'id': '', 'name': node, 'host': host}
    netw_info = execute(node_network_info, hosts=[host,], ourhost=ourhost)
    if not netw_info:
        return XResponse({'error': 'node not found'})
    node_addr = netw_info[host]['virt_ip']
    ret = execute(kill_tmux_session, host=node_addr, name=name)
    return XResponse({'result': ret[node_addr]})


@lck 
@httpdigest
def memory(request,node,host):
    r = request
    pre = pre_from_req(r)
    user = getuser(r)
    print('pre=%s'%pre)
    if not pre.search(node): return Error403("no permissions to access %s , not in %s"%(OVPN_HOST,usergroups(user)))

    rt = execute(getmem,node,host=host)[host]
    return XResponse({'result':rt})

@lck 
@httpdigest
def memory_update(request,node,host):
    r = request
    pre = pre_from_req(r)
    user = getuser(r)
    if not pre.search(node): return Error403("no permissions to access %s"%OVPN_HOST)

    prev = execute(getmem,node,host=host)[host]

    rfn = '/tmp/'+str(int(random.random()*10000))+'.xml'
    def dumpxml(node,fn): run('virsh dumpxml %s > %s'%(node,fn))
    rt = execute(dumpxml,node,rfn,host=host)
    newval = request.params.get('memory')
    def modxml(fn,newval): 
        run('cat %s | xmlstarlet ed -u "//memory" -v %s | xmlstarlet ed -u "//currentMemory" -v %s > %s.new'%(fn,newval,newval,fn))
    rt = execute(modxml,rfn,newval,host=host)
    def redefine(fn): run('virsh define %s'%(fn))
    rt = execute(redefine,rfn+'.new',host=host)
    after = execute(getmem,node,host=host)[host]
    def rmfn(fn): run('rm %s'%fn)
    post = execute(rmfn,fn=rfn,host=host)
    return XResponse({'result':'ok','note':'please shut off and restart the machine to see changes.','prev':prev})
