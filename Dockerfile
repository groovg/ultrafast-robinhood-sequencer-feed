# docker build -t rhfeed .
# docker run --rm rhfeed --feed mainnet --feed mainnet
#
# Builds with UltrafastSecp256k1 for x86-64-v3 (AVX2, BMI2, ADX), which covers any
# x86 server from the last ten years. For the machine you build on, use MARCH=native.
FROM rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang cmake ninja-build \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY scripts scripts
ARG MARCH=x86-64-v3
RUN scripts/build-ufsecp.sh /ufsecp "$MARCH"
COPY . .
RUN UFSECP_LIB_DIR=/ufsecp/build cargo build --release --locked --features ufsecp

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libstdc++6 libatomic1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/rhfeed /usr/local/bin/rhfeed
USER nobody
ENTRYPOINT ["rhfeed"]
