#!/bin/bash
set -u
SSH="ssh -i $HOME/.ssh/id_ed25519 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 ts@127.0.0.1"
$SSH 'echo CONNECTED; uname -a; id; cat /etc/os-release | head -2; ls /lib/modules; nproc; free -m | head -2; df -h / | tail -1; ip -br a | head'
