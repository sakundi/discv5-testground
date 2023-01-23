!/bin/bash

nohup testground daemon &
testground run composition -f compositions/eclipse-attack-monopolizing-by-incoming-nodes.toml
echo "Attack started!..."
