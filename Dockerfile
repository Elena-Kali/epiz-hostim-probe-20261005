FROM node:22-bookworm-slim AS node
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libstdc++6 && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
WORKDIR /probe
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY probe.py .
USER 65534:65534
CMD ["python", "-u", "probe.py"]
