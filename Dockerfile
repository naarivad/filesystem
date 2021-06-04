FROM rust as build
ENV PKG_CONFIG_ALLOW_CROSS=1

WORKDIR /usr/src/filesystem
COPY . .

RUN cargo install --path .

FROM gcr.io/distroless/cc-debian10
WORKDIR /usr/local/bin
COPY --from=build /usr/local/cargo/bin/filesystem .
COPY --from=build /usr/src/filesystem/templates ./templates

CMD ["filesystem"]