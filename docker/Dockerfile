FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 MPLBACKEND=Agg
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY configs ./configs
RUN pip install --no-deps . && useradd --create-home --uid 10001 app
USER app
# 1161/udp: guard in front of the emulated controller (non-privileged SNMP port); 8000/tcp: operator API
EXPOSE 1161/udp 8000
CMD ["ntcip-guard", "serve", "--listen", "0.0.0.0:1161"]
