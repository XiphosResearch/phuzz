FROM alpine:edge

RUN apk --update add \
        python \
        py2-pip \
        strace \
        php5 \
        php5-xdebug \
        php5-dom \
        php5-ctype \
        php5-curl \
        php5-gd \
        php5-intl \
        php5-mcrypt \
        php5-json \
        php5-opcache \
        php5-pdo \
        php5-pdo_mysql \
        php5-posix \
        php5-xml \
        php5-iconv \
        php5-phar \
        php5-openssl \
    && rm -rf /var/cache/apk/*

RUN pip install requests

COPY . /phuzz

VOLUME /source

ENTRYPOINT ["/phuzz/phuzz.py"]