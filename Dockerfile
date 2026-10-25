# syntax=docker/dockerfile:1.7
#
# AEGIS OMEGA SHIELD - production image (API + analyst console + shipped detection model).
#
#   docker build -t aegis-omega:1.0.0 .
#
# Stages
#   web      builds the React console (web/dist) with the locked npm dependency tree
#   builder  builds the Python wheel and a self-contained virtualenv (postgres + llm extras);
#            it uses the full Python image of the same Debian release, which also provides the
#            OpenMP runtime (libgomp) that LightGBM needs
#   runtime  python slim, non-root (uid 10001), no compilers, no apt step, no package caches
#
# Building behind a TLS-inspecting proxy (common inside operator networks): pass the
# proxy's CA bundle as a BuildKit secret; it is used for downloads only and never lands
# in an image layer:
#
#   docker build --secret id=extra_ca,src=/path/to/corporate-ca.pem -t aegis-omega:1.0.0 .
#
# Base images are referenced by tag for readability; the release workflow records the
# resolved digests in the SBOM and signs the pushed image.

ARG PYTHON_VERSION=3.12
ARG NODE_IMAGE=node:22-slim

# ------------------------------------------------------------------------------ web
FROM ${NODE_IMAGE} AS web
WORKDIR /src/web
ENV npm_config_fund=false npm_config_audit=false npm_config_update_notifier=false
COPY web/package.json web/package-lock.json ./
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca npm_config_cafile=/run/secrets/extra_ca; fi; \
    npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build && test -f dist/index.html

# ------------------------------------------------------------------------------ builder
FROM python:${PYTHON_VERSION} AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /src
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY pyproject.toml ./
COPY aegis/ ./aegis/
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install --upgrade pip setuptools wheel \
 && pip wheel --no-deps --wheel-dir /wheels . \
 && pip install /wheels/*.whl "psycopg[binary]>=3.1" "anthropic>=0.40" \
 && pip uninstall -y pip setuptools wheel \
 && python -m compileall -q /opt/venv \
 && mkdir -p /opt/runtime-libs \
 && cp -L "$(ldconfig -p | awk '/libgomp\.so\.1 /{print $NF; exit}')" /opt/runtime-libs/libgomp.so.1

# ------------------------------------------------------------------------------ runtime
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG VERSION=1.0.0
ARG REVISION=unknown
LABEL org.opencontainers.image.title="AEGIS OMEGA SHIELD" \
      org.opencontainers.image.description="Evidence-first network and device security intelligence for operators (shadow-mode by default)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="LicenseRef-AEGIS-Commercial" \
      org.opencontainers.image.vendor="AEGIS OMEGA"

# OpenMP runtime for LightGBM, copied from the builder (same Debian release, same glibc).
COPY --from=builder /opt/runtime-libs/ /usr/local/lib/
RUN ldconfig \
 && groupadd --system --gid 10001 aegis \
 && useradd --system --uid 10001 --gid aegis --home-dir /var/lib/aegis --shell /usr/sbin/nologin aegis \
 && mkdir -p /var/lib/aegis /opt/aegis \
 && chown aegis:aegis /var/lib/aegis \
 && chmod 0750 /var/lib/aegis

COPY --from=builder /opt/venv /opt/venv
COPY --from=web /src/web/dist /opt/aegis/web/dist
COPY models/sentinel-default /opt/aegis/models/sentinel-default
COPY deploy/tools /opt/aegis/tools

ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AEGIS_DATA_DIR=/var/lib/aegis \
    AEGIS_WEB_DIST=/opt/aegis/web/dist \
    AEGIS_MODEL_DIR=/opt/aegis/models/sentinel-default \
    AEGIS_LOG_FORMAT=json

USER 10001:10001
WORKDIR /var/lib/aegis
VOLUME ["/var/lib/aegis"]
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=4 \
  CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"]

ENTRYPOINT ["aegis"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
