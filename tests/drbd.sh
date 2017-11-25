#!/bin/bash
HYPERV="$1"
N1="$2"
N2="$3"
IMG="$4"
[[ $HYPERV != "" ]] || { echo "must include hypervisor host on which to deploy" ; exit 1; }
[[ $N1 != "" ]] || { echo "must include first drbd host" ; exit 1; }
[[ $N2 != "" ]] || { echo "must include second drbd host" ; exit 1; }
[[ $IMG != "" ]] || { echo "must include image, e.g ubuntu-16.04-large.img" ; exit 1; }
(for H in $(echo "$N1" ; echo "$N2") ; do 
    fab -H $HYPERV undefine:$H,$HYPERV ; 
    fab -H $HYPERV destroy:$H ; 
    fab -H $HYPERV create_node:$H,$IMG
done) &&
echo '###### DONE CREATING' &&
fab -R drbd drbd_setup:1,1 &&
echo '###### DONE DRBD SETUP' &&
fab -H $N1 drbd_failover_test:test,$N2,overwrite=1 &&
echo '###### DONE INITIAL FAILOVER TEST'
