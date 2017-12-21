#!/bin/bash
# this performs a reset operation on hetzner hardware hosts via the hetzner robot.
# you must have the HETZNER_LOGIN , HETZNER_PASSWD variables set in your config
if [[ "$1" == ""  || "$2" == "" ]] ; then
    echo "usage:"
    echo "vendor/hetzner/reset.sh {ssh_machine_name} {sw|hw}"
    exit 1
    fi
IP="$(egrep -A3  $1"([[:space:]]*)$" conf_repo/ssh_config | egrep '^([[:space:]]*)HostName' | awk '{print $2}')"
LP="$(python -c 'from config import HETZNER_LOGIN as l,HETZNER_PASSWD as p ; print("%s:%s"%(l,p))')"
curl -u $LP "https://robot-ws.your-server.de/reset/"$IP -d "type="$2 | jq '.'
