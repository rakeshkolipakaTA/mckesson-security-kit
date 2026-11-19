# Scanner image for Python-based tools (Bandit, pip-audit, modelscan) and the red-team harness. Versions come from versions.env via build args.
FROM python:3.12-slim
ARG BANDIT_VERSION
ARG PIP_AUDIT_VERSION
ARG MODELSCAN_VERSION
RUN pip install --no-cache-dir "bandit[toml,sarif]==${BANDIT_VERSION}" "pip-audit==${PIP_AUDIT_VERSION}" "modelscan==${MODELSCAN_VERSION}"
ENV HOME=/tmp PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
