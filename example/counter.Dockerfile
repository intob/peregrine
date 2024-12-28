FROM alpine:3.21
COPY ../zig-out/bin/counter /bin/
ENTRYPOINT ["counter"]
