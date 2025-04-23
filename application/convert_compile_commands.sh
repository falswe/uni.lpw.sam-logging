#!/bin/sh
jq '[ .[] | .command = (.command | sub("-fno-reorder-functions"; "") | sub("-mfp16-format=ieee"; "") | sub("-fno-defer-pop"; "") | sub("-fno-freestanding"; "")) ]' $1 > $2
