#!/usr/bin/env python
from __future__ import print_function
from past.builtins import cmp
import sys,re

r = re.compile('^(?P<date_month>[^ ]+) (?P<date_day>[0-9]+) (?P<date_hour>[0-9]+):(?P<date_minute>[0-9]+):(?P<date_second>[0-9]+) (?P<log_name>[^ ]+) (?P<log_facility>[^ ]+): (?P<log_contents>.*)$')

def np(name):
    return '(?P<%(e)s_name>[^/]+)/(?P<%(e)s_addr>[^:]+):(?P<%(e)s_port>[0-9]+)'%{'e':name}
def ap(p,pat,name):
    pat = pat.replace('?P<','?P<'+name+'__')
    p.append(pat)
    return p

p = ['(?P<client_name>[^/]+)/(?P<client_addr>[^:]+):(?P<client_port>[0-9]+)',
     '\[(?P<origin_name>.+)\] (?P<origin_contents>.+)',
     'imuxsock (?P<loss_state>lost (?P<loss_count>[0-9]+)|begins to drop) messages from pid (?P<loss_pid>[0-9]+) due to rate-limiting',
     'MULTI: REAP range (?P<reap_from>[0-9]+) -> (?P<reap_to>[0-9]+)',


     #'\(root\) CMD \((?P<cmd_contents>.*)\)$',
     '(?P<packet_err_prefix>Authenticate/Decrypt packet error): (?P<packet_err_prefix_reason>packet HMAC authentication failed)',
     'TLS (?P<tls_err_type>State |)Error: incoming packet authentication failed from \[AF_INET\](?P<tls_err_addr>[^:]+):(?P<tls_err_port>[0-9]+)',



     '(?P<seq_broken_addr>[^:]+):(?P<seq_broken_port>[0-9]+) ACK output sequence broken: (?P<seq_broken_contents>.+)',
     #'(?P<inactivity_timeout_addr>[^:]+):(?P<inactivity_timeout_port>[0-9]+) \[UNDEF\] Inactivity timeout \(--ping-restart\), restarting',
     '(?P<multi>MULTI): (?P<multi_contents>multi_close_instance called)',
     '(?P<pid_packet_id_free>PID packet_id_free)',
     #'(?P<multi_addr>[^:]+):(?P<multi_port>[0-9]+) MULTI: C2C/MCAST/BCAST',
     '(?P<read_event>read UDPv4) \[EHOSTUNREACH\|EHOSTUNREACH\]: (?P<read_event_contents>.*)',

     #'(?P<warning_addr>[^:]+):(?P<warning_port>[0-9]+) WARNING: \'(?P<warning_field>link-mtu|tun-mtu)\' is used inconsistently(?P<warning_contents>.+)',
     '',
     

     #'igal.s/62.219.65.26:34514 TLS: tls_pre_encrypt: key_id=7',
     ]
p = ap(p,np('state')+' Adaptive compression state (?P<contents>OFF|ON)','adaptive_compression_state')
p = ap(p,np('')+' TLS: (?P<type>tls_pre_decrypt|tls_pre_encrypt), (?P<contents>.+), IP=\[AF_INET\](?P<addr>[^:]+):(?P<ip_port>[0-9]+)','tls')
p = ap (p,np('')+' TLS: (?P<type>tls_pre_decrypt|tls_pre_encrypt): (?P<key_info>.+)','tls2')
p = ap (p,'(?P<addr>[^:]+):(?P<port>[0-9]+) UDPv4 WRITE \[(?P<qty>[0-9]+)\] to \[AF_INET\](?P<to_addr>[^:]+):(?P<to_port>[0-9]+): (?P<contents>.+)','write')
p = ap (p,'(?P<sent_addr>[^:]+):(?P<sent_port>[0-9]+) SENT PING','ping')
p = ap (p,'(?P<addr>[^:]+):(?P<port>[0-9]+) UDPv4 READ \[(?P<qty>[0-9]+)\] from \[AF_INET](?P<from_addr>[^:]+):(?P<from_port>[0-9]+): (?P<contents>.+)','read')
p = ap (p,     '(?P<name>[^/]+)/(?P<addr>[^:]+):(?P<port>[0-9]+) RECEIVED PING PACKET','ping_recv')
p = ap (p,      np('')+' GET INST BY VIRT: (?P<hostname>[^ ]+) \[failed\]','get_inst_by_virt_3')
p = ap (p,      np('')+' \[(?P<user>[^\]]+)\] Inactivity timeout \(--ping-restart\), restarting','inactivity_timeout_2')
p = ap (p, np('')+' MULTI: bad source address from client \[(?P<ipv6>[^\]]+)\], packet dropped','bad_source_address')
p = ap (p,      '(?P<addr>[^:]+):(?P<port>[0-9]+) SIGUSR1\[soft,ping-restart\] received, client-instance restarting','sigusr1')
p = ap (p, np('')+' GET INST BY VIRT: (?P<ip>[^ ]+) -> '+np('2')+' via (?P<ip2>.+)','get_inst_by_virt_2')
p = ap (p, 'GET INST BY VIRT: (?P<hostname>[^ ]+) -> '+np('get_inst_by_virt_4')+' via (?P<hostname2>[^ ]+)','get_inst_by_virt_4')
p = ap (p, 'GET INST BY REAL: (?P<addr>[^:]*)\:(?P<port>[^ ]+) \[(?P<state>.+)\]','resolve_fail')
p = ap(p,     np('')+' TUN WRITE \[(?P<tun_write_qty>[0-9]+)\]','tun_write')
p = ap(p,     np('')+' TUN READ \[(?P<tun_read_qty>[0-9]+)\]','tun_read')
p = ap(p, np('')+' MULTI: C2C/MCAST/BCAST','multi2')
cre = '^('+'|'.join(p)+')$'

#print cre
c = re.compile(cre)
cnt=0
karr={}
for ln in sys.stdin:
    cnt+=1
    d = ln.strip()
    res = r.search(d)
    if not res:
        print('COULD NOT PARSE LOGLINE:',d)
        continue
    lc = res.groupdict()['log_contents']
    #print(lc)
    cres = c.search(lc)
    if cres:
        #print cres.groupdict()
        pass
    else:
        print('COULD NOT RESOLVE:',lc)
        #print 'WHOLE LINE:',d
        #raise Exception(cnt)
        continue
    for k,v in list(cres.groupdict().items()):
        if v is None: continue
        if k not in karr:karr[k]=0
        if 'print' in sys.argv:
            if 'ts' in sys.argv:
                print(res.groupdict()['date_hour'],res.groupdict()['date_minute'],k,v)
            else:
                print(k,v)
        karr[k]+=1

if 'digest' in sys.argv:
    karr_sorted = sorted(list(karr.items()),lambda x,y: cmp(x[1],y[1]))
    for k,v in karr_sorted:
        print(k,v)
    print('done going through ',cnt)
