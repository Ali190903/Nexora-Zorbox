FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Create unprivileged user for service
RUN useradd -r -u 10001 -g root svc || adduser --uid 10001 --disabled-password --gecos "" svc || true

RUN apt-get update && \
    apt-get install -y --no-install-recommends libmagic1 && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir .

COPY app ./app

# Ensure upload directory exists and owned by svc
RUN mkdir -p /app/app/uploads && chown -R 10001:0 /app

EXPOSE 8080
USER 10001:0
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
