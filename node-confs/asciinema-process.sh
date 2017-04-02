#!/bin/bash

# the following issues need to be closed for us to start worrying about hardening etc.
# until then, the user can fuck up his session's logs at will.
# https://github.com/asciinema/asciinema/issues/127
# https://github.com/asciinema/asciinema/issues/82

# #these are in place to make sure the users cannot remove their sessions previous or current logs
# function harden_files() {
#     for FN in `find /var/log/asciinema/ -iname '*log' -type f ! -user root` ; do
#     #echo "file:"$FN
# 	ls -lad $FN
# 	chown root:root $FN
# 	chmod og-rw $FN
# 	chattr +a $FN
#     done

#     for FN in `find /var/log/asciinema -type d ! -user root` ; do
#     #echo "dir:"$FN
# 	ls -lad $FN
# 	chown root:root $FN
# 	chmod o+rwx $FN
#     done
# }

# checking for file openness, changing attributes etc is disabled until the features in the comment on topic arrive into asciinema.

function copy_files() {
SSHCMD="ssh -i $HOME/.ssh/id_rsa-jumphost-logcollector"
#let's copy the finished sessions
# this part must be run from the host that receives the backups
    for HOST in `cat ~/jumphosts.txt` ; do
	$SSHCMD root@$HOST 'find /var/log/asciinema -type f -size +1c' | \
#	    while read filename ; do $SSHCMD "fuser -s $filename" || echo $filename ; done | \
#	    while read filename ; do $SSHCMD "chattr -a $filename" ; echo $filename ; done | \
	    tr '\n' '\0'  | \
	    rsync -e "$SSHCMD" -avxtz --remove-sent-files --files-from=- --from0 root@$HOST:/ ~/$HOST
	done
}
function display_status() {
echo 'archive:' ; find ~ -type f | wc -l
echo 'src:' ; find /var/log/asciinema -type f | wc -l
}
#harden_files
while (true) ; do
    copy_files
    sleep 1
    done