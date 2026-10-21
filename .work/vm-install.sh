#!/bin/bash
set -u
SSH="ssh -i $HOME/.ssh/id_ed25519 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20 ts@127.0.0.1"
$SSH 'sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential "linux-headers-$(uname -r)" iperf3 tcpdump ethtool python3 >/dev/null 2>&1; echo "install rc=$?"; ls -d /usr/src/linux-headers-$(uname -r); which gcc make iperf3 tcpdump; idle=$(cat /proc/loadavg); echo "load: $idle"'
