# ovpn-admin

Simple web UI to manage OpenVPN users, their certificates & routes in Linux. While backend is written in Go, frontend is based on Vue.js.

***DISCLAIMER!** This project was created for experienced users (system administrators) and private (e.g., protected by network policies) environments only. Thus, it is not implemented with security in mind (e.g., it doesn't strictly check all parameters passed by users, etc.). It also relies heavily on files and fails if required files aren't available.*

## Features

* Adding, deleting OpenVPN users (generating certificates for them);
* Revoking/restoring/rotating users certificates;
* Generating ready-to-user config files;
* Providing metrics for Prometheus, including certificates expiration date, number of (connected/total) users, information about connected users;
* (optionally) Specifying CCD (`client-config-dir`) for each user;
* (optionally) Operating in a master/slave mode (syncing certs & CCD with other server);
* (optionally) Specifying/changing password for additional authorization in OpenVPN;
* (optionally) Specifying the Kubernetes LoadBalancer if it's used in front of the OpenVPN server (to get an automatically defined `remote` in the `client.conf.tpl` template).
* (optionally) Storing certificates and other files in Kubernetes Secrets (**Attention, this feature is experimental!**).
* (optionally) IPv6: dual-stack web UI listener, IPv6 pool for VPN clients, static IPv6 addresses and IPv6 routes in CCD (see [IPv6](#ipv6)).

### Screenshots

Managing users in ovpn-admin:
![ovpn-admin UI](https://raw.githubusercontent.com/palark/ovpn-admin/master/img/ovpn-admin-users.png)

An example of dashboard made using ovpn-admin metrics:
![ovpn-admin metrics](https://raw.githubusercontent.com/palark/ovpn-admin/master/img/ovpn-admin-metrics.png)

## Installation

### 1. Docker

There is a ready-to-use [docker-compose.yaml](https://github.com/palark/ovpn-admin/blob/master/docker-compose.yaml), so you can just change/add values you need and start it with [start.sh](https://github.com/palark/ovpn-admin/blob/master/start.sh).

Requirements:
You need [Docker](https://docs.docker.com/get-docker/) and [Docker Compose v2](https://docs.docker.com/compose/install/) (`docker compose`) installed.
The example enables IPv6 for the containers, which needs a Docker Engine with IPv6 support (27.0+ recommended) and IPv6 enabled in the host kernel (see [IPv6 with Docker Compose](#docker-compose) to turn it off).

Commands to execute:

```bash
git clone https://github.com/palark/ovpn-admin.git
cd ovpn-admin
./start.sh
```
#### 1.1
Ready docker images are published to the GitHub Container Registry: [`ghcr.io/palark/ovpn-admin/ovpn-admin`](https://github.com/palark/ovpn-admin/pkgs/container/ovpn-admin%2Fovpn-admin) for ovpn-admin and [`ghcr.io/palark/ovpn-admin/openvpn`](https://github.com/palark/ovpn-admin/pkgs/container/ovpn-admin%2Fopenvpn) for openvpn-server. Tags are the release tags (`$VERSION`, e.g. `v2.0.2`) and `master` (the latest build of the master branch). Images are built for `linux/amd64` and `linux/arm64`.

### 2. Building from source

Requirements. You need Linux with the following components installed:
- [golang](https://golang.org/doc/install) 1.26 or newer
- [nodejs/npm](https://nodejs.org/en/download/package-manager/) 22.18+ or 24.11+ (LTS)

The frontend and templates are embedded into the binary with `go:embed`, no C toolchain is needed (`build.sh` builds with `CGO_ENABLED=0`; set `GOARCH`, e.g. `GOARCH=arm64 ./build.sh`, to cross-compile). Only 64-bit platforms (`amd64`, `arm64`) are supported.

Commands to execute:

```bash
git clone https://github.com/palark/ovpn-admin.git
cd ovpn-admin
./bootstrap.sh
./build.sh
./ovpn-admin 
```

(Please don't forget to configure all needed params in advance.)

### 3. Prebuilt binary

You can also download and use prebuilt binaries from the [releases](https://github.com/palark/ovpn-admin/releases/latest) page — just choose a relevant tar.gz file (`linux-amd64` or `linux-arm64`).


## Notes
* This tool uses external calls for `bash`, `coreutils` and `easy-rsa`, thus **Linux systems only are supported** at the moment.
* To enable additional password authentication, provide `--auth.password` and `--auth.db="/etc/easyrsa/pki/users.db"` flags and install [openvpn-user](https://github.com/pashcovich/openvpn-user/releases/tag/v1.0.9) v1.0.9 and `sqlite3` (needed to upgrade a `users.db` created by openvpn-user v1.0.4 or older, see [Upgrade notes](#upgrade-notes)). Both should be available in your `$PATH` and be executable (`+x`). Two-factor authentication (TOTP) of openvpn-user is not supported by ovpn-admin.
* OpenVPN server certificates are not listed and cannot be managed (revoked, deleted, rotated, downloaded) as users: a certificate with the extended key usage `serverAuth` and without `clientAuth`, as `easyrsa build-server-full` issues it, whatever its common name is (e.g. the host name), and the CN `server`. A new user cannot take the CN of a server certificate either.
* If you use `--ccd` and `--ccd.path="/etc/openvpn/ccd"` and plan to use static address setup for users, do not forget to provide `--ovpn.network="172.16.100.0/24"` (and `--ovpn.network.ipv6="fd00:16:100::/64"` for IPv6) with valid openvpn-server network.
* The Docker images ship [openvpn-user](https://github.com/pashcovich/openvpn-user) v1.0.9 and `sqlite3`. An existing `users.db` of openvpn-user v1.0.4 is migrated automatically on start, see [Upgrade notes](#upgrade-notes).
* If you want to pass all the traffic generated by the user, you need to edit `ovpn-admin/templates/client.conf.tpl` and uncomment `redirect-gateway def1`.
* Tested with openvpn-server versions 2.4 and 2.5 and with tls-auth mode only.
* Not tested with Easy-RSA version > 3.0.8.
* Status of user connections update every 28 seconds.
* Master-replica synchronization and additional password authentication do not work with `--storage.backend=kubernetes.secrets` - **WIP**

## IPv6

IPv6 is optional and disabled by default (except the web UI listener). An IPv4 pool is always required, IPv6 is added on top of it.

### ovpn-admin

* `--listen.host` defaults to an empty value: ovpn-admin listens on all interfaces, IPv4 and IPv6. Use `0.0.0.0` (IPv4 only), `::` or e.g. `::1` to restrict it.
* `--ovpn.network.ipv6` (`OVPN_NETWORK_IPV6`) sets the IPv6 pool of the OpenVPN server, i.e. the same value as `server-ipv6` in the OpenVPN config, e.g. `fd00:16:100::/64` (prefix length 64-124). An empty value (default) disables IPv6 support. When it is set, the `ipv6` module is enabled (`/api/server/settings`) and the UI offers IPv6 fields.
* `--ovpn.network` (`OVPN_NETWORK`) accepts `172.16.100.0/24` as well as `172.16.100.0/255.255.255.0`. Both networks are validated at startup, ovpn-admin exits on an invalid value.
* IPv6 literals in addresses must be written in brackets:
  * `--ovpn.server="[2001:db8::1]:1194:udp"` (becomes `remote 2001:db8::1 1194 udp` in client configs). Hostnames and IPv4 addresses work as before. Supported protocols: `udp`, `udp4`, `udp6`, `tcp`, `tcp4`, `tcp6`, `tcp-client`, `tcp4-client`, `tcp6-client`;
  * `--mgmt="main=[::1]:8989"`;
  * `--master.host="http://[fd00::1]:8080"`.
* The status of connected clients is read with `status 3` from the management interface, the statistics include the IPv6 virtual address of a client (`VirtualAddressIPv6`).

### Static addresses and routes (CCD)

With `--ccd` every user can get a static IPv4 address (inside `--ovpn.network`, except the network, broadcast and server addresses) and, when IPv6 is enabled, a static IPv6 address (inside `--ovpn.network.ipv6`, except the network and server addresses). The server addresses are read from the running OpenVPN servers (the `state` command of their management interfaces, i.e. the addresses of `server`/`ifconfig` and `server-ipv6`/`ifconfig-ipv6` in their configs), so a server with its own address, e.g. a `dev tap` server with `ifconfig 172.29.11.10 255.255.255.0`, is protected as well; while a server has not reported an address of a family, network+1 (the address OpenVPN takes with `server`/`server-ipv6`) is reserved instead. Static addresses must be unique across users. Routes are IPv4 (address + dotted netmask, `10.1.0.0` / `255.255.0.0`) or IPv6 (address + prefix length, `fd00:1::` / `64`, the CIDR form `fd00:1::/64` is accepted too). A generated CCD file looks like:

```
ifconfig-push 172.16.100.10 255.255.255.0
ifconfig-ipv6-push fd00:16:100::10/64
push "route 10.1.0.0 255.255.0.0" # lan
push "route-ipv6 fd00:1::/64" # lan6
```

Custom CCD templates (`--templates.ccd-path`) using `.ClientAddress` and `.CustomRoutes` keep working. Templates also get `.ClientAddressIPv6` (`dynamic` or an address), `.Netmask` (the dotted netmask of `--ovpn.network`), `.IPv6PrefixLen` (the prefix length of `--ovpn.network.ipv6`) and the `.IsIPv6` method of a route (`Mask` of an IPv6 route is the prefix length), see [templates/ccd.tpl](templates/ccd.tpl).

The CCD API (`GET api/user/ccd?username=...`, `POST api/user/ccd/apply`) is backward compatible and has one new field, `ClientAddressIPv6` (missing or empty means `dynamic`):

```json
{"User":"alice","ClientAddress":"172.16.100.10","ClientAddressIPv6":"fd00:16:100::10","CustomRoutes":[{"Address":"10.1.0.0","Mask":"255.255.0.0","Description":"lan"},{"Address":"fd00:1::","Mask":"64","Description":"lan6"}]}
```

### OpenVPN server container

The `openvpn` image (`Dockerfile.openvpn`, [setup/configure.sh](setup/configure.sh)) is configured with environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OVPN_SERVER_NET`, `OVPN_SERVER_MASK` | `172.16.100.0`, `255.255.255.0` | IPv4 pool for VPN clients (`--server`) |
| `OVPN_SERVER_NET6` | empty (IPv6 disabled) | IPv6 pool for VPN clients in CIDR format (`--server-ipv6`), e.g. `fd00:16:100::/64`. Adds an `ip6tables` MASQUERADE rule for the pool and enables IPv6 forwarding |
| `OVPN_PROTO` | `tcp` | Transport of the listener (`--proto`): `tcp` listens on IPv4 only, `tcp6` is dual-stack and accepts clients over IPv4 and IPv6. Independent of `OVPN_SERVER_NET6` |
| `OVPN_PASSWD_AUTH` | `false` | Enable the additional password authentication |
| `OVPN_ROLE` | `master` | `slave` waits for the first successful sync of its ovpn-admin with the master instead of generating new certificates |

IPv6 forwarding (`net.ipv6.conf.all.forwarding=1`) has to be enabled in the network namespace of the container. `configure.sh` tries to set it, but `/proc/sys` is usually read-only in containers, so set it from the outside (e.g. `sysctls` in Docker Compose), otherwise only a warning is printed and IPv6 traffic of the clients is not routed. Use the same pool for `OVPN_SERVER_NET6` and ovpn-admin's `OVPN_NETWORK_IPV6`.

### Docker Compose

[docker-compose.yaml](docker-compose.yaml) runs the example with IPv6 enabled:

* the user-defined network `ovpn` has `enable_ipv6: true` with the subnets `172.20.0.0/24` and `fd00:172:20::/64` ([docker-compose-slave.yaml](docker-compose-slave.yaml) uses `172.21.0.0/24` and `fd00:172:21::/64` and reaches the master via `http://172.20.0.1:8080`);
* the `openvpn` service gets the `net.ipv6.conf.all.disable_ipv6=0` and `net.ipv6.conf.all.forwarding=1` sysctls, `OVPN_SERVER_NET6="fd00:192:168:100::/64"` and `OVPN_PROTO="tcp6"`;
* the `ovpn-admin` service gets `OVPN_NETWORK_IPV6="fd00:192:168:100::/64"`.

To run it without IPv6, remove `enable_ipv6` and the IPv6 subnet of the network, the `sysctls`, `OVPN_SERVER_NET6` and `OVPN_NETWORK_IPV6`, and set `OVPN_PROTO` to `tcp` (or remove it).

### Kubernetes (Helm chart)

The [Helm chart](charts/openvpn-admin) has the following IPv6-related values:

* `openvpn.subnetIPv6` - IPv6 pool for VPN clients (`server-ipv6`), passed to ovpn-admin as `--ovpn.network.ipv6`;
* `openvpn.dualStack` - `tcp6-server` listener and `ipFamilyPolicy: PreferDualStack` for the Services (`openvpn.ipFamilies` optionally sets `ipFamilies`);
* `openvpn.externalIPs` - list of IPv4 and/or IPv6 addresses for `inlet: ExternalIP` (the legacy `openvpn.externalIP` still works), they are also used as `remote` addresses of the client configs;
* `podSecurityContext` - IPv6 forwarding in the pod is an unsafe sysctl in Kubernetes: allow `net.ipv6.conf.all.forwarding` on the kubelets and set it with `podSecurityContext.sysctls`.

```bash
helm install openvpn-admin charts/openvpn-admin \
  --set openvpn.subnetIPv6=fd00:16:200::/64 \
  --set openvpn.dualStack=true \
  --set openvpn.inlet=ExternalIP \
  --set 'openvpn.externalIPs={203.0.113.10,2001:db8::10}'
```

## Upgrade notes

* **openvpn-user v1.0.4 → v1.0.9** (only relevant with password authentication, `--auth.password` / `OVPN_PASSWD_AUTH=true`). openvpn-user v1.0.9 adds the columns `secret` and `app_configured` to `users.db`. The column `secret` is added without a default value, so for every user whose password was saved by openvpn-user v1.0.4 or older it is `NULL`, and `openvpn-user auth` of v1.0.9 rejects these users (`converting NULL to string is unsupported`) — they cannot connect to the VPN any more. Users created by v1.0.9 are not affected. Additionally `openvpn-user db-migrate` does nothing on a database created by v1.0.4 until `openvpn-user db-init` has created the `migrations` table, and until the database is migrated `openvpn-user create` reports success without saving the user.
  * The Docker images handle this: `setup/configure.sh` of the openvpn image and ovpn-admin itself (when started with `--auth.password` or `--auth.db-init`) run `db-init` and `db-migrate` on start and then replace `NULL` in `secret` with an empty string (the value v1.0.9 stores for new users). All steps are idempotent.
  * If you install openvpn-user yourself, back up `users.db` and run once after the upgrade, before VPN clients connect:
    ```bash
    openvpn-user db-init --db.path=/etc/easyrsa/pki/users.db
    openvpn-user db-migrate --db.path=/etc/easyrsa/pki/users.db
    sqlite3 /etc/easyrsa/pki/users.db "UPDATE users SET secret = '' WHERE secret IS NULL;"
    ```
  * ovpn-admin checks whether a user has a password record with `openvpn-user list --all` (`openvpn-user check` of v1.0.9 prints nothing).
* **32-bit platforms are not supported any more**: Docker images are built for `linux/amd64` and `linux/arm64` only (no `linux/arm/v7`, `linux/arm/v8`), release binaries for `linux-amd64` and `linux-arm64` only (no `linux-386`, `linux-arm`).
* `GET api/user/ccd` answers `400` for an invalid username and `404` for an unknown user (it used to answer `200` with an empty CCD). An invalid JSON body of `POST api/user/ccd/apply` is rejected with `422`, like the other CCD validation errors (plain text message).
* `api/user/create` fails if the certificate cannot be issued (with `--auth.password` also if the password cannot be saved; the password is removed again if the certificate fails), `api/user/revoke` fails if `easyrsa revoke` fails. Both used to report success.
* Rotating or deleting a user whose certificate is not revoked (active or expired; the UI offers it for expired users, the API for any) revokes the certificate first: it used to stay valid after a delete (the user could still connect), and rotating an expired user failed because its files were still in `issued/`, `private/` and `reqs/`. Unrevoke restores `certs_by_serial/<serial>.pem` as well.
* `api/user/change-password` always answers valid JSON: `{"status": "ok"|"error", "message": "..."}`.
* `ovpn_client_bytes_sent` and `ovpn_client_bytes_received` are the sums over all sessions of a common name (`duplicate-cn`), `ovpn_client_connection_info` has a series for each virtual address (IPv4 and IPv6) of a session. Metric names and labels are unchanged.
* `ConnectedSince` and `LastRef` (`api/user/statistic`) are formatted as `yyyy-MM-dd HH:mm:ss` in the local time zone of ovpn-admin for all OpenVPN versions.
* With `--storage.backend=kubernetes.secrets` clearing the static address and routes of a user also clears the CCD file of OpenVPN, and the address can be assigned to another user right away.
* The web UI is served with `Cache-Control: no-cache` and an `ETag` (it used to be cached for 30 days), so browsers load the new UI right after an upgrade.

## Usage

```
usage: ovpn-admin [<flags>]


Flags:
  --[no-]help                   Show context-sensitive help (also try
                                --help-long and --help-man).
  --listen.host=""              host for ovpn-admin; empty means all
                                interfaces (IPv4 and IPv6), e.g. 0.0.0.0, ::,
                                ::1 ($OVPN_LISTEN_HOST)
  --listen.port="8080"          port for ovpn-admin ($OVPN_LISTEN_PORT)
  --listen.base-url="/"         base url for ovpn-admin ($OVPN_LISTEN_BASE_URL)
  --role="master"               server role, master or slave ($OVPN_ROLE)
  --master.host="http://127.0.0.1"  
                                URL for the master server, IPv6 hosts
                                in brackets: http://[fd00::1]:8080
                                ($OVPN_MASTER_HOST)
  --master.basic-auth.user=""   user for master server's Basic Auth
                                ($OVPN_MASTER_USER)
  --master.basic-auth.password=""  
                                password for master server's Basic Auth
                                ($OVPN_MASTER_PASSWORD)
  --master.sync-frequency=600   master host data sync frequency in seconds
                                ($OVPN_MASTER_SYNC_FREQUENCY)
  --master.sync-token=TOKEN     master host data sync security token
                                ($OVPN_MASTER_TOKEN)
  --ovpn.network="172.16.100.0/24"  
                                IPv4 NETWORK/MASK_PREFIX (or NETWORK/NETMASK)
                                for OpenVPN server ($OVPN_NETWORK)
  --ovpn.network.ipv6=""        IPv6 NETWORK/PREFIX for OpenVPN server
                                (server-ipv6), e.g. fd00:16:100::/64; empty
                                disables IPv6 ($OVPN_NETWORK_IPV6)
  --ovpn.server=HOST:PORT:PROTOCOL ...  
                                HOST:PORT:PROTOCOL for OpenVPN server,
                                IPv6 hosts in brackets: [2001:db8::1]:1194:udp;
                                can have multiple values ($OVPN_SERVER)
  --[no-]ovpn.server.behindLB   enable if your OpenVPN server is behind
                                Kubernetes Service having the LoadBalancer type
                                ($OVPN_LB)
  --ovpn.service=openvpn-external ...  
                                the name of Kubernetes Service having the
                                LoadBalancer type if your OpenVPN server is
                                behind it ($OVPN_LB_SERVICE)
  --mgmt=main=127.0.0.1:8989 ...  
                                ALIAS=HOST:PORT for OpenVPN server
                                mgmt interface, IPv6 hosts in brackets:
                                main=[::1]:8989; can have multiple values
                                ($OVPN_MGMT)
  --metrics.path="/metrics"     URL path for exposing collected metrics
                                ($OVPN_METRICS_PATH)
  --easyrsa.path="./easyrsa"    path to easyrsa dir ($EASYRSA_PATH)
  --easyrsa.index-path=""       path to easyrsa index file; empty means
                                <easyrsa.path>/pki/index.txt ($OVPN_INDEX_PATH)
  --easyrsa.bin-path="easyrsa"  path to easyrsa script ($EASYRSA_BIN_PATH)
  --[no-]ccd                    enable client-config-dir ($OVPN_CCD)
  --ccd.path="./ccd"            path to client-config-dir ($OVPN_CCD_PATH)
  --templates.clientconfig-path=""  
                                path to custom client.conf.tpl
                                ($OVPN_TEMPLATES_CC_PATH)
  --templates.ccd-path=""       path to custom ccd.tpl
                                ($OVPN_TEMPLATES_CCD_PATH)
  --[no-]auth.password          enable additional password authentication
                                ($OVPN_AUTH)
  --auth.db="./easyrsa/pki/users.db"  
                                database path for password authentication
                                ($OVPN_AUTH_DB_PATH)
  --[no-]auth.db-init           enable database initialization if db user not
                                exists or size is 0 ($OVPN_AUTH_DB_INIT)
  --log.level="info"            set log level: trace, debug, info, warn,
                                error (default info) ($LOG_LEVEL)
  --log.format="text"           set log format: text, json (default text)
                                ($LOG_FORMAT)
  --storage.backend="filesystem"  
                                storage backend: filesystem, kubernetes.secrets
                                (default filesystem) ($STORAGE_BACKEND)
  --client-cert.expiration-days="3650"  
                                Expiration period of OpenVPN client
                                certificates in days, the period will shrink
                                automatically to the CA expiration period
                                ($CLIENT_CERT_EXPIRATION_DAYS)
  --[no-]version                Show application version.
```

## Authors

ovpn-admin was originally created in [Flant](https://github.com/flant/) and used internally for years.

In March 2021, it [went public](https://medium.com/flant-com/introducing-ovpn-admin-a-web-interface-to-manage-openvpn-users-d81705ad8f23) and was still developed in Flant.
Namely, [@vitaliy-sn](https://github.com/vitaliy-sn) created its first version in Python, and [@pashcovich](https://github.com/pashcovich) rewrote it in Go.

In November 2024, this project was moved to [Palark](https://github.com/palark/), which is currently responsible for its maintenance and development.
