FROM python:3.8-slim

# 1. Instalar nmap y dependencias esenciales
RUN apt-get update && apt-get install -y \
    nmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 2. Verificar la instalación de nmap
RUN which nmap && nmap --version

# 3. Configurar el PATH explícitamente
ENV PATH="/usr/bin/nmap:${PATH}"

# Configurar entorno
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar aplicación
COPY . .

EXPOSE 5200

CMD ["gunicorn", "--bind", "0.0.0.0:5200", "--workers", "4", "app:app"]