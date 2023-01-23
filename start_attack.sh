!/bin/bash

echo "Cleaning docker..."
docker ps --all | grep Exited | gawk '{print $1}' | xargs sudo docker rm -f
docker ps --all | grep Created | gawk '{print $1}' | xargs docker rm -
echo "Starting testground..."
nohup testground daemon &
echo "Starting attack!..."
testground run composition -f compositions/eclipse-attack-monopolizing-by-incoming-nodes.toml
echo "Attack started!"
