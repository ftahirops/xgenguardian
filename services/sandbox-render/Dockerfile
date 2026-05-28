# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/playwright/python:v1.46.0-jammy
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir fastapi uvicorn[standard] playwright boto3 pydantic httpx
COPY app ./app
EXPOSE 8002
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
