FROM alpine:3.21

ENV USER_ID=1000 \
    GROUP_ID=1000 \
    APP_DIR=/app

WORKDIR ${APP_DIR}

RUN addgroup -g ${GROUP_ID} appgroup && \
    adduser -u ${USER_ID} -G appgroup -H -D -s /bin/sh appuser

COPY --chown=appuser:appgroup ./example/dirserver/static/ ${APP_DIR}/example/dirserver/static/
COPY --chown=appuser:appgroup ./zig-out/bin/dirserver ${APP_DIR}/

RUN chown -R appuser:appgroup ${APP_DIR} && \
    chmod 755 ${APP_DIR} && \
    chmod 755 ${APP_DIR}/dirserver

USER appuser

ENTRYPOINT ["/app/dirserver"]
