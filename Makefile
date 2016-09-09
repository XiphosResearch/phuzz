DKR_TAG=harryr/phuzz

all:
	./phuzz.py

build:
	docker build -t $(DKR_TAG) .

run:
	docker run -ti  $(DKR_TAG) /bin/sh
