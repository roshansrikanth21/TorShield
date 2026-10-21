#!/bin/bash
set -e
SSH="ssh -i $HOME/.ssh/id_ed25519 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 ts@127.0.0.1"
SCP="scp -i $HOME/.ssh/id_ed25519 -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
$SSH 'mkdir -p /home/ts/ts'
$SCP /mnt/k/tor-project/module/LKM/*.c /mnt/k/tor-project/module/LKM/Makefile ts@127.0.0.1:/home/ts/ts/
$SCP /mnt/k/tor-project/.work/vm-src/stage1.sh ts@127.0.0.1:/home/ts/ts/
$SSH 'sudo bash /home/ts/ts/stage1.sh' 2>&1
