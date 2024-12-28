FROM alpine:3.21
COPY ./zig-out/bin/basic /bin/
ENTRYPOINT ["basic"]
