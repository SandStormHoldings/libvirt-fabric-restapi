#!/bin/bash
IFS=$'\n'
for LN in $(egrep -v '^#' conf_repo/openvpnusers.txt) ; do 
    KN=$(echo "$LN" | awk '{print $1}')
    EM=$(echo "$LN" | awk '{print $2}')
    if [ ! -z "$1" ] && [ "$1" != "$KN" ]; then 
	#echo "skipping ; $KN != $1"
	continue
	fi
    echo "$KN => $EM"
    fab -H "$(cat conf_repo/openvpnhost.txt)" client_openvpn:$KN,1,$EM
    done