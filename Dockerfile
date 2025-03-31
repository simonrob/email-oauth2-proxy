FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    python3-dev \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --root-user-action=ignore --upgrade pip \
  && pip install --root-user-action=ignore --prefix=/app/deps emailproxy


FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /app/deps /usr/local

EXPOSE 1993 1995 1587

CMD ["python", "-m", "emailproxy", "--external-auth", "--no-gui"]
