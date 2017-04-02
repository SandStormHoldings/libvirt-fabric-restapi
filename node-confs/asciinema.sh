#!/bin/bash
# set up the logdir
LOGDIR="/var/log/asciinema/"$(whoami)"/"$(date '+%Y-%m-%d')
mkdir -p "$LOGDIR"
# determine the target logfile
LOGFILE=$LOGDIR"/"$(echo $SSH_CLIENT | cut -f1 -d' ')"-"$(date '+%H%M')"-"$(shuf -i 1000-10000 -n 1)".log"
# launch the logging as the primary shell, with tmux being the interactive command run
[ -z $ASCIINEMA_REC ] && exec /usr/local/bin/asciinema rec -w 3 -y "$LOGFILE" -c 'tmux attach || tmux new

'
