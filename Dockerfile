FROM rust:1 as builder

RUN apt-get update && apt-get upgrade -y && apt-get -y install libssl-dev

WORKDIR /usr/src/nwd
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y nmap sudo libssl-dev net-tools && rm -rf /var/lib/apt/lists/*

RUN echo -e "Cmnd_Alias NMAP = /usr/bin/nmap\nALL ALL=(ALL) NOPASSWD: NMAP" > /etc/sudoers.d/nmap

RUN mkdir /opt/nwd
COPY --from=builder /usr/local/cargo/bin/network_discover /opt/nwd/network_discover
COPY --from=builder /usr/src/nwd/static /opt/nwd/static

WORKDIR /opt/nwd
CMD [ "./network_discover" ]
