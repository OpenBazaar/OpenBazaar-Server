TESTPATH=./dht/tests ./db/tests

.PHONY: all unittest

all: unittest

unittest:
	nosetests --with-coverage -s -v --cover-package=dht --cover-package=db --cover-package=guidutils --cover-package=market --cover-package=protos --cover-package=seed --cover-inclusive $(TESTPATH)
