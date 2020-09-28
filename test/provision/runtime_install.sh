#!/bin/bash
set -e

HOST=$(hostname)
PROVISIONSRC="/tmp/provision"

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "${PROVISIONSRC}/helpers.bash"

sudo bash -c "echo MaxSessions 200 >> /etc/ssh/sshd_config"
sudo systemctl restart ssh

sudo mkdir -p /var/lib/cilium
sudo cp "${PROVISIONSRC}"/VMCA.crt /var/lib/cilium/ca-etcd.crt
sudo cp "${PROVISIONSRC}"/runtime.crt /var/lib/cilium/etcd-client.crt
sudo cp "${PROVISIONSRC}"/runtime.key /var/lib/cilium/etcd-client.key
sudo tee /var/lib/cilium/etcd-config.yaml <<EOF
---
trusted-ca-file: /var/lib/cilium/ca-etcd.crt
key-file: /var/lib/cilium/etcd-client.key
cert-file: /var/lib/cilium/etcd-client.crt
endpoints:
- https://clustermesh-apiserver:32379
EOF

"${PROVISIONSRC}"/dns.sh
"${PROVISIONSRC}"/compile.sh
"${PROVISIONSRC}"/wait-cilium.sh
