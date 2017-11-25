#!/bin/bash
HYPERV="$1"
ROLE="$2"
ADMHOST="$3"
IMG="$4"
[[ $HYPERV != "" ]] || { echo "must include hypervisor host on which to deploy" ; exit 1; }
[[ $ROLE != "" ]] || { echo "must include role. e.g ceph" ; exit 1; }
[[ $ADMHOST != "" ]] || { echo "must include admin host" ; exit 1; }
[[ $IMG != "" ]] || { echo "must include image, e.g ubuntu-16.04-large.img" ; exit 1; }
echo '###### COMMENCING'
(for H in $(fab getrole:ceph | cut -f1 -d '.' | egrep -v '^Done' | egrep -v '^$') ; do 
    fab -H $HYPERV undefine:$H,$HYPERV ; 
    fab -H $HYPERV destroy:$H ; 
    fab -H $HYPERV create_node:$H,$IMG,2524288
done) \
 &&
echo '###### INSTALLING SSH KEYS' &&
fab -R "$ROLE" put_ssh_privkey:id_rsa-ceph,,id_rsa &&
fab -R "$ROLE" authorized_keys_add:/root/.ssh/authorized_keys,conf_repo/id_rsa-ceph.pub &&
echo '###### INSTALLING LIBVIRT' &&
sleep 10 &&
echo '###### INITIAL HOST LIBVIRT INSTALL' &&
fab -R "$ROLE" install:dhcpd=,network= &&
echo '###### DONE CREATING' &&
fab -P -R "$ROLE" ceph_install:1 &&
echo '###### DONE CEPH SETUP' &&
fab -H $ADMHOST ceph_deploy_new:cephile &&
echo '###### DONE ceph instance creation' &&
fab -P -R "$ROLE" ceph_deploy_install &&
echo '###### DONE ceph_deploy_install' &&
fab -H $ADMHOST ceph_deploy_monitor:/root/cephile &&
echo '###### ssh get hosts to know eachother' && 
fab -P -R "$ROLE" "ssh_connect_group:"$ROLE &&
echo '###### ceph deploy admin:' &&
fab -R "$ROLE" ceph_deploy_admin:$ADMHOST,/root/cephile &&
echo '###### creating loop devices:' &&
fab -R "$ROLE" loop_create:/root/tst.img,7G,/dev/loop0 &&
echo '####### ceph deploying osd' &&
fab -R "$ROLE" ceph_deploy_osd_prepare:$ADMHOST,cephile,loop0 &&
echo '####### ceph fixing loop journal symlinks' &&
fab -R "$ROLE" ceph_fix_loop_journal_symlink &&
echo '###### ceph setting up libvirt to work with rbd' &&
fab -H $ADMHOST ceph_setup_libvirt &&
echo '###### all done?' 

# get an image from $HYPERV
# ssh $ADMHOST 'nc -l 6000 | pv | rbd import - libvirt-pool/ubuntu'
# ssh $HYPERV 'pv /var/lib/libvirt/images/'$IMG | nc $ADMHOST 6000'

# here's how you migrate:
# fab -H $ADMHOST migrate:vasja,$DSTHOST,nocopy=1,changesecret=1

# create a snapshot of our template to be able to clone from
# rbd snap create libvirt-pool/ubuntu@1
# rbd snap protect libvirt-pool/ubuntu@1

# setup a new virt
# fab -H $NEWHOST create_node_rbd:vasja,$ADMHOST,image_clone=libvirt-pool/ubuntu@1