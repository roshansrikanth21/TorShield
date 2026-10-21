#!/bin/bash
set -e
SSH="ssh -i $HOME/.ssh/id_ed25519 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 ts@127.0.0.1"
SCP="scp -i $HOME/.ssh/id_ed25519 -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
$SCP /mnt/k/tor-project/.work/vm-src/pcap.py /mnt/k/tor-project/.work/vm-src/stage2.sh ts@127.0.0.1:/home/ts/ts/
$SSH 'sudo bash /home/ts/ts/stage2.sh' 2>&1
