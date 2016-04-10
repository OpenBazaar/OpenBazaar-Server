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

echo "Setting username"
set_username $USERNAME

echo "Setting password"
set_password $PASSWORD

echo "Executing ${@}"
exec "$@"
