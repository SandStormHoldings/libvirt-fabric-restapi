#!/usr/bin/env python
from builtins import zip
import re
import logging
from fabric.api import env
# we use an ssh config file called ssh_config by default.
import os,sys

env.ssh_config_path=os.path.join(os.path.dirname(__file__),'ssh_config')
assert os.path.exists(env.ssh_config_path)
env.use_ssh_config = True

HYPERVISOR_HOSTNAME_PREFIX='hyperv'

# override this to include specific hypervisor hosts in your setup 
env.roledefs['kvm'] = []

main_network = None

# regular expressions to facilitate parsing the ssh config file
hostre = re.compile('^([\s]*)Host (.+)')
ipre = re.compile('^([\s]*)HostName (.+)')
confcont = open(env.ssh_config_path,'r').read().split("\n")
hosts = [r.group(2).strip() for r in filter(lambda x: x,[ipre.search(r) for r in confcont])]
ips = [r.group(2).strip() for r in filter(lambda x: x,[hostre.search(r) for r in confcont])]
# parsed dictionary from ssh config includes hosts and their ips 
HOSTS = dict(list(zip(ips,hosts)))

zero_offset=30
gate = lambda x: '%s.%s.1' % (main_network, x and x or zero_offset-x)
internal_gate = lambda x: '%s.%s.2' % (main_network, x and x or zero_offset-x)
netrange = lambda x, y: '%s.%s.2 %s.%s.254' % (main_network, x and x or zero_offset-x, main_network, y)

# default starting parameters for newly created virtual machines
DEFAULT_RAM='524288'
DEFAULT_VCPU=2

# override this in the local config to setup ip forwarding to the virtual hosts 
FLOATING_IPS=[] #format as follows: [('hostname','internal ip','external ip'),]
IPV6={}

LOG_LEVEL = logging.DEBUG
#digest auth
DIGEST_REALM=None
SECRET_KEY=None
DIGEST_TIMEOUT_IN_SECONDS=86400
AUTH_DB_FILE='auth.json'
DNS_HOST = None
OVPN_HOST = 'OpenVpn'

DHCPD_DOMAIN_NAME=''

# these are your virtual machine images. format 'name': 'disk image filename'
# in general, to be workable with by they need to satisfy the following requirements
IMAGES={}

LOWERED_PRIVILEGES=[]
DEFAULT_SEARCH='ezd.lan'
OVPN_KEYDIR='/root/openvpn_keys'
HOST_GATEWAYS={}
snmpd_network='0.0.0.0/0'

FORWARDED_PORTS=[]

ssh_passwords={}

DEFAULT_GATEWAY=None #?
JUMPHOST_EXTERNAL_IP=None
OVPN_KEY_SENDER='openvpn@crazywinnersvip.com'

SSH_HOST_KEYNAME='id_rsa-host' # hypervisor ssh key
SSH_VIRT_KEYNAME='id_rsa-virt' # virtual node ssh key
SSH_KEYNAMES=[SSH_HOST_KEYNAME,SSH_VIRT_KEYNAME]

# this is the default format for virtual disk templates from which we instantiate hosts. qcow2 can be used just as well
IMAGE_FORMAT='raw'

ALERTS_RECIPIENT=None
ALERTS_RECIPIENT_NAME=None

DRBD_RESOURCES={}
DRBD_SALT=None
NOTES={}

# import the local overrides of the defaults above.
from config_noodles import *
try:
    from local_config import *
except ImportError:
    pass

# the below section make some deductions from both default and overriden config. it is important for it to be run *at the end* of all configs.

assert len(FLOATING_IPS)== len(set([k[2] for k in FLOATING_IPS])),"external ips not unique"
assert len(FLOATING_IPS)== len(set([k[1] for k in FLOATING_IPS])),"more than a single floating ip per-host?" 

VLAN_GATEWAYS={} ; INTERNAL_GATEWAYS={} ; VLAN_RANGES={} ; HOST_IDX={}
for ip in [ip for ip in ips if HOST_PREFIX in ip]:
    try:
        i = int(ip.replace(HOST_PREFIX,''))
    except ValueError:
        continue
    HOST_IDX[ip]=i
    VLAN_GATEWAYS[ip]=gate(i)
    INTERNAL_GATEWAYS[ip]=internal_gate(i)
    VLAN_RANGES[ip]=netrange(i,i)
    
if __name__=='__main__' and len(sys.argv)>1:
    print(locals()[sys.argv[1]])
