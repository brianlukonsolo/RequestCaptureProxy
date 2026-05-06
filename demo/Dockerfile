FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir Flask==3.1.0

COPY demo/request_logger.py /app/request_logger.py

RUN useradd --create-home --uid 10003 demouser && chown -R demouser:demouser /app
USER demouser

EXPOSE 18080

CMD ["python", "/app/request_logger.py"]
