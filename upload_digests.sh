#!/bin/bash
for H in $(egrep -v '^\#' conf_repo/htdigest-hosts.txt | awk '{print $1}') ; do 
    scp -F ssh_config  conf_repo/digest.pw $H:/etc/apache2/digest.pw
    done
