#!/bin/bash

# This script update the dns servers to use google ones.
set -e

sudo systemctl disable systemd-resolved.service
sudo service systemd-resolved stop

echo "updating /etc/resolv.conf"

cat <<EOF > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
EOF

echo "Adding clustermesh-apiserver to /etc/hosts"

cat <<EOF >> /etc/hosts

192.168.36.11 clustermesh-apiserver
EOF
