# OpenBazaar Server
[![Build Status](https://travis-ci.org/OpenBazaar/OpenBazaar-Server.svg?branch=master)](https://travis-ci.org/OpenBazaar/OpenBazaar-Server) [![Coverage Status](https://coveralls.io/repos/OpenBazaar/OpenBazaar-Server/badge.svg?branch=master&service=github)](https://coveralls.io/github/OpenBazaar/OpenBazaar-Server?branch=master) [![Slack Status](https://openbazaar-slackin-drwasho.herokuapp.com/badge.svg)](https://openbazaar-slackin-drwasho.herokuapp.com)

This repo contains the OpenBazaar networking daemon that can be used to access the p2p network. It establishes connections and maintains
a Kademlia style DHT. Rest and websocket APIs are available for clients to communicate with the daemon.

## Install

Pre-built installers which bundle the client and server components can be found [here](https://github.com/OpenBazaar/OpenBazaar-Installer/releases).

Depending on your system configuration you may need to install some additional dependencies. You can find more detailed, OS specific, instructions [here](https://slack-files.com/T02FPGBKB-F0KJU1CLX-cbbcf8a02c).

To install just this server:

```bash
sudo pip install -r requirements.txt
```

## Usage

```bash
python openbazaard.py start --help
```

```
usage: python openbazaard.py start [<args>]

Start the OpenBazaar server

optional arguments:
  -h, --help            show this help message and exit
  -d, --daemon          run the server in the background as a daemon
  -t, --testnet         use the test network
  -l LOGLEVEL, --loglevel LOGLEVEL
                        set the logging level [debug, info, warning, error,
                        critical]
  -p PORT, --port PORT  set the network port
  -a ALLOWIP, --allowip ALLOWIP
                        only allow api connections from this ip
  -r RESTAPIPORT, --restapiport RESTAPIPORT
                        set the rest api port
  -w WEBSOCKETPORT, --websocketport WEBSOCKETPORT
                        set the websocket api port
  -b HEARTBEATPORT, --heartbeatport HEARTBEATPORT
                        set the heartbeat port
  --pidfile PIDFILE     name of the pid file
```

## Docker

- Install [Docker](https://docs.docker.com/engine/installation/).
- Install [DockerCompose](https://docs.docker.com/compose/install/).

#### Set Username and Password
```bash
nano ./docker-compose.yml
```

#### Build and run
```bash
docker-compose up
```

#### Backup
All relevant data will go to
```bash
./data
```

#### SSL Support
- Generate certificate as described [here](https://slack-files.com/T02FPGBKB-F0XK9ND2Q-fc5e6500a3)

- Place the *server.crt* and *server.key* into
```bash
./ssl
```

- Enable SSL in
```bash
./docker-compose.yml
```


## License
OpenBazaar Server is licensed under the [MIT License](LICENSE).
