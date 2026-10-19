# SR-20: One application image for every Python compartment.
#
# Security controls:
# - Base image pinned to an exact Python patch release
# - Exact gunicorn version; all other packages pinned in requirements.txt
# - Only application code is copied: no tests, notes, secrets,
#   certificates or Git history
# - Code is owned by root and read-only to the runtime user
# - Runs as a non-root user (uid 10001, as in Dockerfile.gateway)
# - No default command: each Compose service runs only its own
#   compartment entrypoint (see deploy/ENTRYPOINTS.md)
#
# Build from the repository root:
#   docker build -f deploy/Dockerfile.app -t evp-app .

FROM python:3.11.17-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt gunicorn==26.2.0

# Application code only. Add each workstream's package
# folder here when it reaches main (admin/, ballot/, ...).
COPY *.py ./
COPY platform_security/ ./platform_security/

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin evpuser

USER evpuser
