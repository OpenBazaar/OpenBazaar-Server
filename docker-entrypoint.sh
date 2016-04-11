#!/usr/bin/env bash

set -e

set_username() {
	sedEscapedValue="$(echo "$1" | sed 's/[\/&]/\\&/g')"
	sed -ri "s/^#?(USERNAME\s*=\s*)\S+/\1$sedEscapedValue/" "/OpenBazaar-Server/ob.cfg"
}

set_password() {
	sedEscapedValue="$(echo "$1" | sed 's/[\/&]/\\&/g')"
	sed -ri "s/^#?(PASSWORD\s*=\s*)\S+/\1$sedEscapedValue/" "/OpenBazaar-Server/ob.cfg"
}

set_ssl() {
	sedEscapedValue="$(echo "$1" | sed 's/[\/&]/\\&/g')"
	sed -ri "s/^#?(SSL\s*=\s*)\S+/\1$sedEscapedValue/" "/OpenBazaar-Server/ob.cfg"
}

set_ssl_cert() {
	sedEscapedValue="$(echo "$1" | sed 's/[\/&]/\\&/g')"
	sed -ri "s/^#?(SSL_CERT\s*=\s*)\S+/\1$sedEscapedValue/" "/OpenBazaar-Server/ob.cfg"
}

set_ssl_key() {
	sedEscapedValue="$(echo "$1" | sed 's/[\/&]/\\&/g')"
	sed -ri "s/^#?(SSL_KEY\s*=\s*)\S+/\1$sedEscapedValue/" "/OpenBazaar-Server/ob.cfg"
}

echo "Setting username"
set_username $OB_USERNAME

echo "Setting password"
set_password $OB_PASSWORD

if [ "$OB_SSL" = true ] ; then
	echo "Setting up SSL"
	set_ssl "True"

	echo "Setting SSL cert location"
	set_ssl_cert $OB_SSL_CERT

	echo "Setting SSL key location"
	set_ssl_key $OB_SSL_KEY
fi

echo "Executing ${@}"
exec "$@"
