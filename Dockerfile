FROM ubuntu:16.04
MAINTAINER eiabea <developer@eiabea.com>

# Install required Debian packages
RUN set -ex \
  && apt-get update -q \
  && apt-get install -q -y build-essential libssl-dev libffi-dev python-dev openssl python-pip libzmq3-dev libsodium-dev autoconf automake pkg-config libtool git \
  && apt-get clean autoclean -q -y \
  && apt-get autoremove -q -y \
  && rm -rf /var/lib/apt/lists/* /var/lib/apt/lists/partial/* /tmp/* /var/tmp/*

# Install libzmq from github
RUN git clone https://github.com/zeromq/libzmq
WORKDIR /libzmq
RUN ./autogen.sh
RUN ./configure
RUN make
RUN make install
RUN ldconfig

# Install cryptography
WORKDIR /
RUN pip install cryptography

# Install Openbazaar-Server from current directory
COPY / /OpenBazaar-Server/
WORKDIR /OpenBazaar-Server/
RUN pip install -r requirements.txt -r test_requirements.txt
RUN make

# Copy entrypoint script and mark it executable
COPY ./docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Create Openbazaar user and set correct permissions
RUN adduser --disabled-password --gecos \"\" openbazaar
RUN chown -R openbazaar:openbazaar /OpenBazaar-Server

VOLUME /root/.openbazaar
VOLUME /ssl

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["python", "openbazaard.py", "start"]
