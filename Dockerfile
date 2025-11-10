FROM python:3.11-slim

# Establece el directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema necesarias para face_recognition + OpenCV + Tesseract
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

# Copiar y instalar dependencias de Python
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copiar todo el código al contenedor
COPY . .

# Establecer el puerto esperado por Cloud Run
ENV PORT=8080

# Para producción, usar JSON array en CMD para evitar problemas con señales
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
