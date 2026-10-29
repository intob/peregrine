# comp-uws: uWebSockets v20.74 HTTP "Hello" (built 2026-10-29 as below).
#   docker build -t comp-uws -f Dockerfile .
#   docker build -t comp-uws-ws -f Dockerfile.ws .          # WebSocket echo, uws-load-test
#   docker build -t comp-uws-ws-deflate -f Dockerfile.ws-deflate .   # echo with permessage-deflate
FROM alpine:3.21
RUN apk add --no-cache build-base git zlib-dev linux-headers util-linux-misc
RUN git clone --depth 1 --recursive -b v20.74.0 https://github.com/uNetworking/uWebSockets /src
COPY hello.cpp /src/hello.cpp
WORKDIR /src
RUN make -C uSockets WITH_OPENSSL=0 default && \
    g++ -O3 -march=native -flto -std=c++20 -DUWS_NO_ZLIB -DLIBUS_NO_SSL -IuSockets/src -Isrc hello.cpp uSockets/*.o -o /usr/local/bin/uws-hello -lpthread
