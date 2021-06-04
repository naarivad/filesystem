FROM lukemathwalker/cargo-chef as cacher
WORKDIR /app
COPY ./recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM ghcr.io/naarivad/rust-crosscompiler-arm:latest as builder
WORKDIR /app
COPY . .
COPY --from=cacher /app/target target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN cargo build --release

FROM gcr.io/distroless/cc-debian10
WORKDIR /usr/local/bin
COPY --from=builder /app/target/release/filesystem .
COPY --from=builder /app/templates ./templates

ENTRYPOINT ["filesystem"]