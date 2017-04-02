#!/bin/bash
# this script is intended to be run on the vhost container machines themselves
IS=$(virsh list | grep -v Name | awk '{print $2}')
for I in $IS ; do
	BLKS="$(virsh domblklist $I| egrep -v '^(Target|\-\-\-)' | awk '{print $1}')"
	for BLK in $BLKS ; do
		virsh domblkstat $I $BLK | egrep -v '^$' | sed -e 's/^/'$I' /'
		done
	done

