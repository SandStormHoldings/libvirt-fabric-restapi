#!/bin/bash
for H in $(cat conf_repo/htdigest-hosts.txt | awk '{print $1}') ; do 
    scp conf_repo/digest.pw $H:/etc/apache2/digest.pw
    done