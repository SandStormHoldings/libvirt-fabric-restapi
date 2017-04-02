#!/bin/bash
#!/bin/bash
for H in $(cat conf_repo/htpasswd-hosts.txt | awk '{print $1}') ; do 
    scp conf_repo/htpasswd.pw $H:/var/www/auth/digest.pw
    done