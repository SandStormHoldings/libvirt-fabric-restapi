HOST_PREFIX='hypervisor'
ovpn_client_network='172.14.0.0'
ovpn_internal_addr='10.95.1.1'
ovpn_client_netmask='255.255.0.0'
main_network='10.95'
DIGEST_REALM='hypervisor'
SECRET_KEY=None # SET ME!
IMAGES={'ubuntu-18.04-large.qcow2':{'description':'Ubuntu server 18.04'}}
from fabric.api import env
env.roledefs['kvm']=['hypervisor1']
VLAN_GATEWAYS={'awe':'10.95.1.1'}
VLAN_RANGES={'awe':'10.95.1.2 10.95.1.254'}
HOST_IDX={'hypervisor1':1}
