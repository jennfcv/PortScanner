# Usa una imagen base más ligera con Python 3.8
FROM python:3.8-slim

# Instala nmap y dependencias necesarias primero (para mejor caching)
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Establece variables de entorno para Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Crea y configura el directorio de trabajo
WORKDIR /app

# Copia solo los archivos necesarios primero (para mejor caching)
COPY requirements.txt .

# Instala dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install python-nmap

# Copia el resto de los archivos
COPY . .

# Puerto expuesto (coherente con tu app.py)
EXPOSE 5200

# Usa gunicorn para producción en lugar del servidor de desarrollo de Flask
CMD ["gunicorn", "--bind", "0.0.0.0:5200", "--workers", "4", "app:app"]