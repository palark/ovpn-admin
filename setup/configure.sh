#!/usr/bin/env bash
set -ex

EASY_RSA_LOC="/etc/openvpn/easyrsa"
SERVER_CERT="${EASY_RSA_LOC}/pki/issued/server.crt"

# IPv4 pool for VPN clients (OpenVPN --server)
OVPN_SRV_NET="${OVPN_SERVER_NET:-172.16.100.0}"
OVPN_SRV_MASK="${OVPN_SERVER_MASK:-255.255.255.0}"
# IPv6 pool for VPN clients in CIDR format (OpenVPN --server-ipv6), e.g. fd00:16:100::/64; empty = IPv6 disabled
OVPN_SRV_NET6="${OVPN_SERVER_NET6:-}"
# Listener transport (OpenVPN --proto): tcp = IPv4 only, tcp6 = dual-stack (IPv4 and IPv6 clients)
OVPN_SRV_PROTO="${OVPN_PROTO:-tcp}"


cd "${EASY_RSA_LOC}"

if [ -e "${SERVER_CERT}" ]; then
  echo "Found existing certs - reusing"
else
  if [ "${OVPN_ROLE:-master}" = "slave" ]; then
    echo "Waiting for initial sync data from master"
    # ovpn-admin shares the network namespace of this container and listens on port 8080;
    # wait until it has completed the first successful sync with the master
    while :; do
      last_sync="$(wget -q http://127.0.0.1:8080/api/sync/last/successful -O - || true)"
      if [ -n "${last_sync}" ] && [ "${last_sync}" != "unknown" ]; then
        break
      fi
      sleep 5
    done
  else
    echo "Generating new certs"
    easyrsa --batch init-pki
    cp -R /usr/share/easy-rsa/* "${EASY_RSA_LOC}/pki"
    echo "ca" | easyrsa build-ca nopass
    easyrsa --batch build-server-full server nopass
    easyrsa gen-dh
    openvpn --genkey secret ./pki/ta.key
  fi
fi
easyrsa gen-crl

iptables -t nat -D POSTROUTING -s "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" ! -d "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" -j MASQUERADE || true
iptables -t nat -A POSTROUTING -s "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" ! -d "${OVPN_SRV_NET}/${OVPN_SRV_MASK}" -j MASQUERADE

OVPN_IPV6_ARGS=()
if [ -n "${OVPN_SRV_NET6}" ]; then
  ip6tables -t nat -D POSTROUTING -s "${OVPN_SRV_NET6}" ! -d "${OVPN_SRV_NET6}" -j MASQUERADE || true
  ip6tables -t nat -A POSTROUTING -s "${OVPN_SRV_NET6}" ! -d "${OVPN_SRV_NET6}" -j MASQUERADE

  if [ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" != "1" ]; then
    if ! sysctl -w net.ipv6.conf.all.forwarding=1; then
      echo "WARNING: cannot enable IPv6 forwarding (/proc/sys is read-only?)." \
        "Set net.ipv6.conf.all.forwarding=1 for this container (e.g. docker compose 'sysctls'), otherwise IPv6 traffic of VPN clients is not routed." >&2
    fi
  fi

  OVPN_IPV6_ARGS=(--server-ipv6 "${OVPN_SRV_NET6}")
fi

mkdir -p /dev/net
if [ ! -c /dev/net/tun ]; then
    mknod /dev/net/tun c 10 200
fi

cp -f /etc/openvpn/setup/openvpn.conf /etc/openvpn/openvpn.conf

if [ "${OVPN_PASSWD_AUTH:-false}" = "true" ]; then
  mkdir -p /etc/openvpn/scripts/
  cp -f /etc/openvpn/setup/auth.sh /etc/openvpn/scripts/auth.sh
  chmod +x /etc/openvpn/scripts/auth.sh
  echo "auth-user-pass-verify /etc/openvpn/scripts/auth.sh via-file" | tee -a /etc/openvpn/openvpn.conf
  echo "script-security 2" | tee -a /etc/openvpn/openvpn.conf
  echo "verify-client-cert require" | tee -a /etc/openvpn/openvpn.conf
  # db-init also creates the "migrations" table that openvpn-user >= 1.0.5 needs for db-migrate on a database created by <= 1.0.4
  openvpn-user db-init --db.path="${EASY_RSA_LOC}/pki/users.db" && openvpn-user db-migrate --db.path="${EASY_RSA_LOC}/pki/users.db"
  # the migration adds the column "secret" without a default: users created by openvpn-user <= 1.0.4 get NULL there,
  # and "openvpn-user auth" of 1.0.9 fails for them, so NULL is replaced by an empty string (what 1.0.9 writes for new users)
  sqlite3 "${EASY_RSA_LOC}/pki/users.db" "UPDATE users SET secret = '' WHERE secret IS NULL;"
fi

[ -d "${EASY_RSA_LOC}/pki" ] && chmod 755 "${EASY_RSA_LOC}/pki"
[ -f "${EASY_RSA_LOC}/pki/crl.pem" ] && chmod 644 "${EASY_RSA_LOC}/pki/crl.pem"

mkdir -p /etc/openvpn/ccd

exec openvpn --config /etc/openvpn/openvpn.conf --client-config-dir /etc/openvpn/ccd --port 1194 --proto "${OVPN_SRV_PROTO}" --management 127.0.0.1 8989 --dev tun0 --server "${OVPN_SRV_NET}" "${OVPN_SRV_MASK}" "${OVPN_IPV6_ARGS[@]}"
