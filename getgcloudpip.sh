#!/bin/bash

for LINE in `dig txt _cloud-netblocks.googleusercontent.com +short | tr " " "\n" | grep include | cut -f 2 -d :` ; do dig txt $LINE +short; done | tr " " "\n" | grep ip4  | cut -f 2 -d : | sort -n