# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.12.13-slim-bookworm@sha256:4766d8b510c428e595d74b9cc5bbb2fae8e26316fffb4adc89908d79aacd58a2

FROM ${PYTHON_IMAGE} AS builder
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY defensive_control_plane ./defensive_control_plane
RUN python -m pip wheel --no-cache-dir --no-deps --wheel-dir /wheels .

FROM ${PYTHON_IMAGE} AS runtime
ARG SOURCE_REVISION=UNAVAILABLE
ARG SOURCE_VERSION=0.4.0
LABEL org.opencontainers.image.title="SZL Defensive Control Plane" \
      org.opencontainers.image.description="Evidence-bound defensive security status and governed-response engine" \
      org.opencontainers.image.source="https://github.com/szl-holdings/szl-defensive-control-plane" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.version="${SOURCE_VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CONTROL_PLANE_REVISION=${SOURCE_REVISION}

RUN groupadd --gid 10001 dcp \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /data --shell /usr/sbin/nologin dcp \
    && install -d -o 10001 -g 10001 /data /tmp/dcp
COPY --from=builder /wheels/*.whl /tmp/wheels/
RUN python -m pip install --no-cache-dir /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "-B", "-m", "defensive_control_plane"]
CMD ["serve", "--db", "/data/control-plane.sqlite3", "--mode", "cluster-readonly", "--host", "0.0.0.0", "--port", "8080"]

