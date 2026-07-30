FROM python:3.12-slim

LABEL org.opencontainers.image.title="ssh-honeypot"
LABEL org.opencontainers.image.description="Original educational SSH honeypot (Paramiko-based)"

# Run as an unprivileged user — the honeypot never needs root.
RUN useradd --create-home --shell /usr/sbin/nologin honeypot

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY dashboard/ dashboard/
COPY config/config.yaml config/config.yaml
COPY analyze_logs.py .

RUN mkdir -p logs && chown -R honeypot:honeypot /app

# Generate a host key at build time if one isn't mounted in at runtime.
RUN python3 -c "import paramiko; k = paramiko.RSAKey.generate(2048); k.write_private_key_file('config/host_key')" \
    && chown honeypot:honeypot config/host_key && chmod 600 config/host_key

USER honeypot

EXPOSE 2222

ENTRYPOINT ["python3", "-m", "src.server", "--config", "config/config.yaml"]
