FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir Flask==3.1.0

COPY mocks/mock_service.py /app/mock_service.py

RUN useradd --create-home --uid 10002 mockuser && chown -R mockuser:mockuser /app
USER mockuser

EXPOSE 18081 18082

CMD ["python", "/app/mock_service.py"]
