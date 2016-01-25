[![Build Status](https://travis-ci.org/OpenBazaar/OpenBazaar-Server.svg?branch=master)](https://travis-ci.org/OpenBazaar/OpenBazaar-Server) [![Coverage Status](https://coveralls.io/repos/OpenBazaar/OpenBazaar-Server/badge.svg?branch=master&service=github)](https://coveralls.io/github/OpenBazaar/OpenBazaar-Server?branch=master) [![Slack Status](https://openbazaar-slackin-drwasho.herokuapp.com/badge.svg)](https://openbazaar-slackin-drwasho.herokuapp.com)

- This contains most of the backend networking for OpenBazaar. Going forward, the relevant parts of the current OpenBazaar repo will likely be merged into this.
- If you are looking to contribute to the OpenBazaar backend, this is the repo you want to work on.
- The reference client that interacts with the OpenBazaar backend [is found here](https://github.com/OpenBazaar/OpenBazaar-Client)

Installation notes:
---------------------
You will need Python 2 and pip installed on your system.

Depending on your configuration, you may also need to install python-dev, libffi-dev and python-pylint-common. If you're on Linux, you can do so using your operating system's standard package manager (ex. `sudo apt-get install python-dev`)

To install all Python requirements, run:

```bash
pip install -r requirements.txt
```

Running Unit Tests (optional and non-Windows only)
```
pip install -r test_requirements.txt
bash
make
```

If everything has installed fine, you should get a message that everything went OK.

You can now start the server on testnet (recommended at this point) with:

```bash
python openbazaard.py start --testnet
```

To run on the regular network:

```bash
python openbazaard.py start
```

Various options, including those related to logging and debugging, can be displayed like so:

```bash
python openbazaard.py start --help
```

License
---------------------
OpenBazaar Server is licensed under the [MIT License](LICENSE).
