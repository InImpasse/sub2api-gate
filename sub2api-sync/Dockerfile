FROM postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15 AS postgres-client

# Copy the client and its closed set of dynamic dependencies out of the
# reviewed PostgreSQL 18 image. This stage performs no package-manager or
# network operation, so repository drift cannot change a release build.
RUN set -eux; \
    test "$(psql --version)" = "psql (PostgreSQL) 18.4"; \
    mkdir -p /opt/postgresql/bin /opt/postgresql/lib; \
    cp /usr/local/bin/psql /opt/postgresql/bin/psql; \
    ldd /usr/local/bin/psql \
      | awk '{ for (i = 1; i <= NF; i++) if ($i ~ "^/usr/(local/)?lib/") print $i }' \
      | sort -u \
      | while IFS= read -r library; do \
          cp -L "$library" "/opt/postgresql/lib/$(basename "$library")"; \
        done

FROM python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

LABEL io.sub2api-gate.sync-release="pg18.4-r1" \
      io.sub2api-gate.postgresql-client="18.4" \
      io.sub2api-gate.postgresql-client-source="postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15" \
      io.sub2api-gate.python-source="python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"

COPY --from=postgres-client /opt/postgresql /opt/postgresql
COPY --chmod=0555 psql-wrapper.sh /usr/local/bin/psql

RUN set -eux; \
    test "$(psql --version)" = "psql (PostgreSQL) 18.4"; \
    ! LD_LIBRARY_PATH=/opt/postgresql/lib ldd /opt/postgresql/bin/psql | grep -F "not found"; \
    addgroup -g 65532 -S sub2api_sync; \
    adduser -u 65532 -S -D -H -G sub2api_sync sub2api_sync

WORKDIR /app
COPY --chown=65532:65532 sub2api_sync.py usage_metadata.py ./

USER 65532:65532
EXPOSE 3021
ENTRYPOINT ["python3", "/app/sub2api_sync.py"]
