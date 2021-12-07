FROM rust:1.57-slim-bullseye as builder
WORKDIR /usr/src/certblaze
RUN apt-get update && apt-get install build-essential libssl-dev pkg-config -y
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
COPY --from=builder /usr/local/cargo/bin/certblaze /usr/local/bin/certblaze
EXPOSE 80/tcp
VOLUME ["/certblaze"]
ENV CERTBLAZE_WORKING_DIRECTORY="/certblaze"
ENV CERTBLAZE_CHALLENGE_SERVER_PORT="80"
ENV CERTBLAZE_CHALLENGE_SERVER_ADDRESS="0.0.0.0"
ENTRYPOINT ["/usr/local/bin/certblaze"]
