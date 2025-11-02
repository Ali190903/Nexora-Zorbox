FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir .

COPY app ./app

# Create unprivileged user and own exports
RUN useradd -r -u 10001 -g root svc || adduser --uid 10001 --disabled-password --gecos "" svc || true \
    && mkdir -p /app/app/exports && chown -R 10001:0 /app

EXPOSE 8090
USER 10001:0
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
