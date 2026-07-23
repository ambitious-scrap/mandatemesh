FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MANDATEMESH_DATA_DIR=/app/data

WORKDIR /app
COPY services/api/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: -r /tmp/requirements.txt

COPY services/api /app/services/api
COPY scenarios /app/scenarios
COPY scripts /app/scripts

WORKDIR /app/services/api
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

