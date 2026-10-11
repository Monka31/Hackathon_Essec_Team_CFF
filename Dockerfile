# Image de la plateforme : l'appli + tous les scanners, prête pour EC2.
FROM python:3.12-slim

ARG GITLEAKS_VERSION=8.21.2
ARG TARGETARCH=amd64

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates nodejs npm \
 && rm -rf /var/lib/apt/lists/*

# Gitleaks (secrets)
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64) \
 && curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz" \
    | tar xz -C /usr/local/bin gitleaks

# TruffleHog (secrets, avec vérification d'activité)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin || echo "trufflehog install skipped"

# Snyk CLI (binaire autonome, pas besoin de le télécharger au premier lancement)
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo linux-arm64 || echo linux) \
 && curl -sSL -o /usr/local/bin/snyk "https://downloads.snyk.io/cli/stable/snyk-${ARCH}" \
 && chmod +x /usr/local/bin/snyk

# Semgrep dans son propre environnement Python, pour éviter les conflits de versions avec l'appli
RUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY vibeaudit ./vibeaudit

# Utilisateur sans droits : si un scanner est compromis par un repo piégé, il ne peut rien casser
RUN useradd -m -u 10001 vibe && mkdir -p /data && chown vibe /data
USER vibe
ENV DATA_DIR=/data PYTHONUNBUFFERED=1

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fs http://127.0.0.1:8000/api/health || exit 1
CMD ["python", "-m", "vibeaudit", "serve", "--host", "0.0.0.0", "--port", "8000"]
