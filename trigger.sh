#! /usr/bin/env bash
source /home/guacamole/.venv/bin/activate
/etc/guacamole/trigger.py ${@:1}
