#!/bin/bash

function do_retrieve() {
    echo '*** obtaining virtual nodes'
    fab -R kvm virt_nodes
    echo '*** obtaining keys on virtual nodes'
    cat /tmp/*-nodeslist.txt | awk '{print $3}' | xargs -P10 -I '{}' -- fab -H '{}' authorized_keys_get:1
    
    echo '*** obtaining keys on all hardware nodes'
    fab -R kvm -P authorized_keys_get
    }

# summarize & digest
function do_digest() {
    cd authorized_keys && grep -n "" *  | ../authorized_keys_replace.py | awk -F':' '{print $4,$1,$3}' | sort -k2,1 | sed 's/.txt//g' | sed 's/.ssh\///g'
}

if [[ $_ == $0 ]] ; then
    do_retrieve 2>&1 > /dev/null
    do_digest
    fi

