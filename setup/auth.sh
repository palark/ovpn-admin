#!/usr/bin/env sh

PATH=$PATH:/usr/local/bin
set -e

env

auth_usr=$(head -1 "$1")
auth_passwd=$(tail -1 "$1")

if [ "$common_name" = "$auth_usr" ]; then
  # --flag=value: a separate value starting with "-" (e.g. the password "-secret") is not accepted by openvpn-user
  openvpn-user auth --db.path=/etc/openvpn/easyrsa/pki/users.db --user="${auth_usr}" --password="${auth_passwd}"
else
  echo "Authorization failed"
  exit 1
fi
