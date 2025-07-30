FROM python:3.8-slim

# Instalar nmap con capacidades necesarias
RUN apt-get update && apt-get install -y \
    nmap \
    libcap2-bin \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*

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