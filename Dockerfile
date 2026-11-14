# docker build -t rhfeed .
# docker run --rm rhfeed --feed mainnet --feed mainnet
#
# x86-64-v3 by default (MARCH=native for the build machine). Trixie for a newer clang.
FROM rust:1-trixie AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang cmake ninja-build \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY scripts scripts
ARG MARCH=x86-64-v3
RUN scripts/build-ufsecp.sh /ufsecp "$MARCH"
COPY . .
RUN UFSECP_LIB_DIR=/ufsecp/build RUSTFLAGS="-C target-cpu=$MARCH" \
    cargo build --release --locked --features ufsecp

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libstdc++6 libatomic1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/rhfeed /usr/local/bin/rhfeed
USER nobody
ENTRYPOINT ["rhfeed"]
