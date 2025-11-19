FROM docker.io/timescale/timescaledb:latest-pg17

RUN apk add build-base ca-certificates openssl tar git postgresql-dev clang libc-dev binutils llvm19

RUN git clone https://github.com/citusdata/pg_cron.git
RUN cd pg_cron && make && make install
