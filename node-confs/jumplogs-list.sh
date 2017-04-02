#!/bin/bash
find ~/ -type f | cut -f8,9,10 -d'/'  | awk -F'[/-]' '{print $2,$3,$4,$6,$1,$7,$5}' | sort
