FROM rust:alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev

COPY captcha_icons.cache ./captcha_icons.cache
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:latest

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/ripplit /app/ripplit
COPY --from=builder /build/captcha_icons.cache /app/captcha_icons.cache
COPY build /app/build

EXPOSE 8080

CMD ["/app/ripplit"]
