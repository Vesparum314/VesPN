FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# xray client for the speed probes through VLESS routes (app/speed.py). Same version
# as the servers (config.xray_version); the release's SHA2-256 is checked.
ARG XRAY_VERSION=v26.11.9
RUN python - <<'EOF'
import hashlib, io, os, re, urllib.request, zipfile
v = os.environ.get("XRAY_VERSION") or "${XRAY_VERSION}"
base = f"https://github.com/XTLS/Xray-core/releases/download/{v}/Xray-linux-64.zip"
data = urllib.request.urlopen(base, timeout=120).read()
dgst = urllib.request.urlopen(base + ".dgst", timeout=60).read().decode()
want = re.search(r"SHA2-256=\s*([0-9a-f]{64})", dgst).group(1)
assert hashlib.sha256(data).hexdigest() == want, "xray checksum mismatch"
with zipfile.ZipFile(io.BytesIO(data)) as z:
    with open("/usr/local/bin/xray", "wb") as f:
        f.write(z.read("xray"))
os.chmod("/usr/local/bin/xray", 0o755)
print("xray", v, "installed")
EOF

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000
# DB lives in the /data volume (see docker-compose.yml)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
