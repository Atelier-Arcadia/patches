FROM rust:latest

WORKDIR /patches

COPY Cargo.toml .
COPY Cargo.lock .

# Have dependencies cached by building them for the dummy library first.
COPY docker_dummy.rs .
RUN cargo build --lib

# Now we move our source code in.
# After building our image, running tests will not require that we also
# re-build our dependencies every time.
COPY src/ src/

ENV RUST_BACKTRACE 1

CMD ["cargo", "test", "--features", "integration-test", "--", "--nocapture"]
