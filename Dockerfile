FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias necesarias para face_recognition + OpenCV
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    g++ \
    make \
    libopenblas-dev \
    liblapack-dev \
    libboost-all-dev \
    libssl-dev \
    libffi-dev \
    libgl1 \
    libglib2.0-0 \
    tesseract-ocr \
    tesseract-ocr-spa \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Establece el puerto esperado por Cloud Run
ENV PORT=8080

# Comando de inicio
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT}