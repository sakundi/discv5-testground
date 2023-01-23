!/bin/bash

nohup testground daemon &
testground run composition -f compositions/eclipse-attack-monopolizing-by-incoming-nodes.toml
echo "Attack started!..."
sleep 1000
docker ps --all | grep Exited | gawk '{print $1}' | xargs sudo docker rm -f
docker ps --all | grep Created | gawk '{print $1}' | xargs docker rm -
