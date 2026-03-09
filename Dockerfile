FROM python:3.12-slim

WORKDIR /app

COPY backend/ backend/
COPY Makefile .

EXPOSE 8080

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "backend.app.api_server"]
