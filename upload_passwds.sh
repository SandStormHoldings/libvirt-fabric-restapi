#!/bin/bash

for H in $(egrep -v '^\#' conf_repo/htpasswd-hosts.txt | awk '{print $1}') ; do 
    scp conf_repo/htpasswd.pw $H:/var/www/auth/passwd.pw
    done