#!/bin/bash
AUTHSTRING="$(< .restapi.auth)"
PORT="$(python -c 'from config_noodles import PORT ; print(PORT)')"

curl --digest "${@:2}" 'http://'$AUTHSTRING'@localhost:'$PORT$1
