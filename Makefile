TESTPATH=./dht/tests

.PHONY: all unittest

all: unittest

unittest:
	nosetests --with-coverage --cover-package=dht --cover-package=db --cover-package=guidutils --cover-package=market --cover-package=protos --cover-package=seed --cover-inclusive $(TESTPATH)
