DKR_TAG=harryr/phuzz
PYTHON=python

all:
	$(PYTHON) -mphuzz

lint:
	$(PYTHON) -mpyflakes phuzz
	$(PYTHON) -mpylint -r n -d missing-docstring phuzz

build:
	docker build -t $(DKR_TAG) .

run:
	docker run -ti  $(DKR_TAG) /bin/sh

clean:
	find . -name '*.pyc' | exec rm -rf '{}' ';'
	find . -name '__pycache__' | exec rm -rf '{}' ';'
