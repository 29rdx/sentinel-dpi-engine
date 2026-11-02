FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y cmake g++ libpcap-dev make
WORKDIR /src
COPY . .
RUN cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j4

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libpcap0.8 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/build/sentinel_dpi /usr/local/bin/sentinel_dpi
ENTRYPOINT ["/usr/local/bin/sentinel_dpi"]
