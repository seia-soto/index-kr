#!/bin/sh

setvars() {
  sed "s/__TIMESTAMP__/$(git log -1 --format=%ct)/g" | \
  sed "s/__LAST_MODIFIED__/$(git log -1 --format=%cD)/g" | \
  sed "s/__COMMIT__/$(git log -1 --format=%H)/g"
}

throwerr() {
  if [[ $(wc -c < "$1" | awk '{print $1}') != '0' ]]; then echo "$(cat "$1")" && exit 1; fi
}

# create dist folder
mkdir -p dist/
# generate formatted list
cat header.txt | setvars > dist/list.txt
node transform.mjs list.txt -f=list -c >> dist/list.txt 2> dist/list.err
throwerr dist/list.err
# generate hosts
cat header.hosts | setvars > dist/list.hosts
node transform.mjs dist/list.txt -f=hosts >> dist/list.hosts 2> dist/list.hosts.err
throwerr dist/list.hosts.err
