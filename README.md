# ovpn-admin

Simple web UI to manage OpenVPN users, their certificates & routes in Linux. While backend is written in Go, frontend is based on Vue.js.

Originally created in [Flant](https://flant.com/) for internal needs & used for years, then updated to be more modern and [publicly released](https://medium.com/flant-com/introducing-ovpn-admin-a-web-interface-to-manage-openvpn-users-d81705ad8f23) in March'21. Please note that the project is currently on pause, no new Issues or PRs are accepted.

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

### Screenshots

Managing users in ovpn-admin:
![ovpn-admin UI](https://raw.githubusercontent.com/flant/ovpn-admin/master/img/ovpn-admin-users.png)

An example of dashboard made using ovpn-admin metrics:
![ovpn-admin metrics](https://raw.githubusercontent.com/flant/ovpn-admin/master/img/ovpn-admin-metrics.png)

## Installation

### 1. Docker

There is a ready-to-use [docker-compose.yaml](https://github.com/flant/ovpn-admin/blob/master/docker-compose.yaml), so you can just change/add values you need and start it with [start.sh](https://github.com/flant/ovpn-admin/blob/master/start.sh).

Requirements:
You need [Docker](https://docs.docker.com/get-docker/) and [docker-compose](https://docs.docker.com/compose/install/) installed.

Commands to execute:

```bash
git clone https://github.com/flant/ovpn-admin.git
cd ovpn-admin
./start.sh
```
#### 1.1
Ready docker images available on [Docker Hub](https://hub.docker.com/r/flant/ovpn-admin/tags) 
. Tags are simple: `$VERSION` or `latest` for ovpn-admin and `openvpn-$VERSION` or `openvpn-latest` for openvpn-server

### 2. Building from source

Requirements. You need Linux with the following components installed:
- [golang](https://golang.org/doc/install)
- [packr2](https://github.com/gobuffalo/packr#installation)
- [nodejs/npm](https://nodejs.org/en/download/package-manager/)

Commands to execute:

```bash
git clone https://github.com/flant/ovpn-admin.git
cd ovpn-admin
./bootstrap.sh
./build.sh
./ovpn-admin 
```

(Please don't forget to configure all needed params in advance.)

### 3. Prebuilt binary

You can also download and use prebuilt binaries from the [releases](https://github.com/flant/ovpn-admin/releases/latest) page — just choose a relevant tar.gz file.


## Notes
* this tool uses external calls for `bash`, `coreutils` and `easy-rsa`, thus **Linux systems only are supported** at the moment.
* to enable additional password authentication provide `--auth` and `--auth.db="/etc/easyrsa/pki/users.db`" flags and install [openvpn-user](https://github.com/pashcovich/openvpn-user/releases/latest). This tool should be available in your `$PATH` and its binary should be executable (`+x`).
* master-replica synchronization does not work with `--storage.backend=kubernetes.secrets` - **WIP**
* additional password authentication does not work with `--storage.backend=kubernetes.secrets` -  **WIP**
* if you use `--ccd` and `--ccd.path="/etc/openvpn/ccd"` abd plan to use static address setup for users do not forget to provide `--ovpn.network="172.16.100.0/24"` with valid openvpn-server network 
* tested only with Openvpn-server versions 2.4 and 2.5 with only tls-auth mode
* not tested with EasyRsa version > 3.0.8
* status of users connections update every 28 second(*no need to ask why =)*)

## Usage

```
usage: ovpn-admin [<flags>]

Flags:
  --help                       show context-sensitive help (try also --help-long and --help-man)

  --listen.host="0.0.0.0"      host for ovpn-admin
  (or OVPN_LISTEN_HOST)

  --listen.port="8080"         port for ovpn-admin
  (or OVPN_LISTEN_PORT)

  --listen.base-url="/"        base URL for ovpn-admin web files
  (or $OVPN_LISTEN_BASE_URL)

  --role="master"              server role, master or slave
  (or OVPN_ROLE)

  --master.host="http://127.0.0.1"  
  (or OVPN_MASTER_HOST)       URL for the master server

  --master.basic-auth.user=""  user for master server's Basic Auth
  (or OVPN_MASTER_USER)
 
  --master.basic-auth.password=""  
  (or OVPN_MASTER_PASSWORD)   password for master server's Basic Auth

  --master.sync-frequency=600  master host data sync frequency in seconds
  (or OVPN_MASTER_SYNC_FREQUENCY)

  --master.sync-token=TOKEN    master host data sync security token
  (or OVPN_MASTER_TOKEN)

  --ovpn.network="172.16.100.0/24"  
  (or OVPN_NETWORK)           NETWORK/MASK_PREFIX for OpenVPN server

  --ovpn.server=HOST:PORT:PROTOCOL ...  
  (or OVPN_SERVER)            HOST:PORT:PROTOCOL for OpenVPN server
                               can have multiple values

  --ovpn.server.behindLB       enable if your OpenVPN server is behind Kubernetes
  (or OVPN_LB)                Service having the LoadBalancer type

  --ovpn.service="openvpn-external"  
  (or OVPN_LB_SERVICE)        the name of Kubernetes Service having the LoadBalancer
                               type if your OpenVPN server is behind it

  --mgmt=main=127.0.0.1:8989 ...  
  (or OVPN_MGMT)              ALIAS=HOST:PORT for OpenVPN server mgmt interface;
                               can have multiple values

  --metrics.path="/metrics"    URL path for exposing collected metrics
  (or OVPN_METRICS_PATH)

  --easyrsa.path="./easyrsa/"  path to easyrsa dir
  (or EASYRSA_PATH)

  --easyrsa.index-path="./easyrsa/pki/index.txt"  
  (or OVPN_INDEX_PATH)        path to easyrsa index file

  --ccd                        enable client-config-dir
  (or OVPN_CCD)

  --ccd.path="./ccd"           path to client-config-dir
  (or OVPN_CCD_PATH)

  --templates.clientconfig-path=""  
  (or OVPN_TEMPLATES_CC_PATH) path to custom client.conf.tpl

  --templates.ccd-path=""      path to custom ccd.tpl
  (or OVPN_TEMPLATES_CCD_PATH)

  --auth.password              enable additional password authorization
  (or OVPN_AUTH)

  --auth.db="./easyrsa/pki/users.db"
  (or OVPN_AUTH_DB_PATH)      database path for password authorization
  
  --log.level                  set log level: trace, debug, info, warn, error (default info)
  (or LOG_LEVEL)
  
  --log.format                 set log format: text, json (default text)
  (or LOG_FORMAT)
  
  --storage.backend            storage backend: filesystem, kubernetes.secrets (default filesystem)
  (or STORAGE_BACKEND)
 
  --version                    show application version
```

## Further information

Please feel free to use [issues](https://github.com/flant/ovpn-admin/issues) and [discussions](https://github.com/flant/ovpn-admin/discussions) to get help from maintainers & community.
