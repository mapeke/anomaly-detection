FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nfdump && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ src/
COPY models/ models/
ENV PYTHONPATH=/app/src PYTHONUNBUFFERED=1
CMD ["python", "-m", "nids.pipeline"]
