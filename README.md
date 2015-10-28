[![Build Status](https://travis-ci.org/OpenBazaar/OpenBazaar-Server.svg?branch=master)](https://travis-ci.org/OpenBazaar/OpenBazaar-Server)[![Coverage Status](https://coveralls.io/repos/OpenBazaar/OpenBazaar-Server/badge.svg?branch=master&service=github)](https://coveralls.io/github/OpenBazaar/OpenBazaar-Server?branch=master)

This contains most of the backend networking for openbazaar. Going forward, the relevant parts of the current OpenBazaar repo will likely be merged into this.

If you are looking to contribute to the OpenBazaar backend, this is the repo you want to work on.


Installation notes:
---------------------
You will need Python and pip installed on your system.

Depending on your configuration, you may also need to install python-dev, libffi-dev and python-pylint-common. If you're on Linux, you can do so using your operating system's standard package manager (ex. `sudo apt-get install python-dev`)

To install all Python requirements, run:

```bash
pip install -r requirements.txt
pip install -r test_requirements.txt
```

After that, run:


```bash
make
```

If everything has installed fine, you should get a message that everything went OK.

You can now start the server with:

```bash
python openbazaard.py start
```


