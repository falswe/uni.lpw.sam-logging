#!/bin/sh
jq '[ .[] | .command = (.command | sub("-fno-reorder-functions"; "") | sub("-mfp16-format=ieee"; "") | sub("-fno-defer-pop"; "")) ]' $1 > $2
