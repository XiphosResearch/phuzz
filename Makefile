DKR_TAG=harryr/phuzz

all:
	python -mphuzz

build:
	docker build -t $(DKR_TAG) .

run:
	docker run -ti  $(DKR_TAG) /bin/sh
