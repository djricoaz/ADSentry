# Image unique ADSentry (API + planificateur). Utilisateur non root, système de fichiers en lecture seule
# (cf. appliance/docker-compose.yml).
FROM python:3.13-slim-trixie AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --wheel-dir /wheels ".[appliance]"

FROM python:3.13-slim-trixie
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    ADSENTRY_CONFIG=/etc/adsentry ADSENTRY_STATE=/var/lib/adsentry ADSENTRY_DATA=/var/lib/adsentry/scans \
    OLLAMA_HOST=http://ollama:11434 HOME=/var/lib/adsentry
RUN apt-get update && apt-get install -y --no-install-recommends tzdata ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/adsentry --shell /usr/sbin/nologin adsentry
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels "adsentry[appliance]" && rm -rf /wheels
USER adsentry
WORKDIR /var/lib/adsentry
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1
CMD ["adsentry", "serve", "--host", "0.0.0.0", "--port", "8000"]
