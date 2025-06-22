FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y build-essential manpages-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN mkdir -p /app/data

COPY . .

RUN make

ENV WORKING_DATA_DIR=/app/data

CMD ["./build/cipher_app"]
