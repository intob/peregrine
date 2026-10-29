# peregrine-h3load: curl 8.23 (ngtcp2 1.25 + nghttp3; --http3-only), h2load
# (nghttp2 1.70) with HTTP/3, nginx, Caddy and aioquic (alpine:edge's), for
# HTTP/3 interop, bottleneck runs and benchmarks (bench/scripts/h3-*.sh).
#   docker build -t peregrine-h3load bench/h3
FROM alpine:edge AS build
RUN apk add --no-cache build-base pkgconf openssl-dev nghttp3-dev libev-dev c-ares-dev zlib-dev libxml2-dev jansson-dev curl autoconf automake libtool linux-headers brotli-dev zstd-dev libpsl-dev
WORKDIR /src
RUN curl -fsSL https://github.com/ngtcp2/ngtcp2/releases/download/v1.25.0/ngtcp2-1.25.0.tar.xz | tar xJ && \
    cd ngtcp2-1.25.0 && ./configure --prefix=/opt/q --with-openssl --enable-lib-only && make -j8 && make install
ENV PKG_CONFIG_PATH=/opt/q/lib/pkgconfig
RUN curl -fsSL https://github.com/nghttp2/nghttp2/releases/download/v1.70.0/nghttp2-1.70.0.tar.xz | tar xJ && \
    cd nghttp2-1.70.0 && ./configure --prefix=/opt/q --enable-app --enable-http3 --disable-python-bindings && make -j8 && make install
RUN curl -fsSL https://curl.se/download/curl-8.23.0.tar.xz | tar xJ && \
    cd curl-8.23.0 && ./configure --prefix=/opt/q --with-openssl --with-ngtcp2 --with-nghttp3 --with-nghttp2=/opt/q --without-libpsl && make -j8 && make install

FROM alpine:edge
RUN apk add --no-cache openssl nghttp3 libidn2 libpsl curl nghttp2-libs nginx caddy libev c-ares zlib libxml2 jansson brotli-libs zstd-libs util-linux-misc python3 py3-aioquic libstdc++ libgcc
COPY --from=build /opt/q /opt/q
ENV PATH=/opt/q/bin:$PATH LD_LIBRARY_PATH=/opt/q/lib
