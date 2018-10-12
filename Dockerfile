FROM rust:latest

WORKDIR /patches

COPY Cargo.toml .
COPY src/ src/

CMD ["cargo", "test", "--features", "integration-test"]
