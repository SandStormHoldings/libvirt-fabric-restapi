#!/bin/bash
alias ssh='ssh -F ssh_config'
alias scp='scp -F ssh_config'
alias rsync='rsync -e "ssh -F ssh_config"  ssh_config'
