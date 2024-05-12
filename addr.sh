#!/bin/bash

sed -n 's/^GADGET_PARAM(\([a-z_]*\)_addr);$/\1/p' program.bpf.c | \
while read param ; do
  addr=$(grep ${param} /proc/kallsyms | awk '{print $1}')
  addr=$(dc -e "16i ${addr^^} p")
  if [ -n "$addr" ] ; then
    echo -n "--${param}_addr=${addr} "
  fi
done
echo
