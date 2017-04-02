#!/bin/bash
while (true) ; do 
	cd /home/restapi && bin/python ./runserver.py
	sleep 60
	done
