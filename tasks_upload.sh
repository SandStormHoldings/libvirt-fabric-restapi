#!/bin/bash
#download:
# scp tasks@$(cat conf_repo/tasks.txt):~/participants.org conf_repo/
scp conf_repo/participants.org tasks@$(cat conf_repo/tasks.txt):~/participants.org