#!/bin/bash
#author:hzy
rm -rf data1
./geth --datadir data1 --syncmode fast --hzyshead 10001 --hzystail 400000 --cache.noprefetch --nodiscover
while:
do
 if[$? -ne 0];then
    rm -rf data1
    ./geth --datadir data1 --syncmode fast --hzyshead 10001 --hzystail 400000 --cache.noprefetch --nodiscover
  else
    echo "succesed"
    break
  fi
done
