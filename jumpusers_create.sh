#!/bin/bash
#this creates user accounts and a jumpuser / asciinema env for all those peeps
for LN in `cat conf_repo/jumpusers.txt | egrep -v '^#'` ; do
    JU=$(echo "$LN" | awk -F'[@ ]' '{print $1}')
    EM=$(echo "$LN" | awk '{print $1}')
    if [ ! -z "$1" ] && [ "$1" != "$JU" ]; then 
	#echo "skipping ; $KN != $1"
	continue
	fi
    fab -H "$(< conf_repo/jumphost.txt)" "jumphost_user:"$JU",conf_repo/keydir/"$JU".pub,email="$EM
    done