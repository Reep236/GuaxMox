#! /usr/bin/env bash
apt update
apt install -y python3 python3-venv 

python3 -m venv /opt/guacamole/.venv
/opt/guacamole/.venv/python3 -m pip install requests proxmoxer
