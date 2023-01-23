#!/bin/bash

echo "Cleaning docker..."
docker ps --all | grep Exited  | gawk '{print $1}' | xargs docker rm -f
docker ps --all | grep Created | gawk '{print $1}' | xargs docker rm -f
echo "Starting testground..."
nohup /home/tikuna/go/bin/testground daemon &
echo "Starting attack!..."
/home/tikuna/go/bin/testground run composition -f compositions/eclipse-attack-monopolizing-by-incoming-nodes.toml
echo "Attack started!"
