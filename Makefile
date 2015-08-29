SCRIPTS=./scripts
TESTPATH=./dht/tests ./db/tests ./market/tests

.PHONY: all unittest check

all: check unittest

unittest:
	nosetests -vs --with-coverage --cover-package=dht --cover-package=db --cover-package=market --cover-inclusive $(TESTPATH)

check: pycheck

pycheck: $(SCRIPTS)/pycheck.sh
	$(SCRIPTS)/pycheck.sh
