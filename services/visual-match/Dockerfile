# syntax=docker/dockerfile:1.7
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml .
RUN pip install --no-cache-dir \
    fastapi uvicorn[standard] open-clip-torch torch torchvision Pillow \
    imagehash mmh3 'psycopg[binary,pool]' pgvector httpx pydantic
COPY app ./app
EXPOSE 8003
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
