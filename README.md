# PortScanner - Análisis de Vulnerabilidades con Inteligencia Artificial

Bienvenido a **PortScanner**, una herramienta de análisis de vulnerabilidades de puertos desarrollada en Python con Flask, integrada con tecnologías avanzadas como OpenAI y Nmap. Este sistema web está diseñado para realizar escaneos profundos de puertos, identificar posibles vulnerabilidades, y generar reportes detallados. Funciona en Windows, Linux y Termux.

## Características Principales

- **Inteligencia Artificial**: Uso de OpenAI para analizar y clasificar las vulnerabilidades detectadas.
- **Integración con Nmap**: Escaneos potentes y fiables.
- **Compatibilidad Multiplataforma**: Funciona en Windows, Linux y Termux.
- **Sistema Web Interactivo**: Interfaz amigable y fácil de usar.
- **Reportes Detallados**: Generación de reportes en tiempo real con gráficos y análisis.
- **Código Abierto**: Totalmente gratuito y accesible.

---

## Capturas de Pantalla

### Panel Principal
![Captura de la Interfaz Principal](https://raw.githubusercontent.com/Pericena/PortScanner/refs/heads/main/screencapture/screencapture-127-0-0-1-5200-2024-12-29-19_29_35.png)

### Reporte de Vulnerabilidades
![Reporte de Vulnerabilidades](https://raw.githubusercontent.com/Pericena/PortScanner/refs/heads/main/screencapture/screencapture-127-0-0-1-5200-scan-2024-12-29-19_33_20.png)

---

## Instalación

### Requisitos Previos
1. Python 3.8 o superior
2. Flask
3. Nmap instalado en el sistema
4. Acceso a internet para utilizar OpenAI

### Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/Pericena/PortScanner.git
   cd PortScanner
   ```

2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

   Asegúrate de que `requirements.txt` incluye lo siguiente:
   ```text
   Flask
   nmap
   openai
   pyyaml
   ```

3. Configura las credenciales de OpenAI:
   - Crea un archivo `.env` en el directorio raíz.
   - Añade tu clave de API de OpenAI:
   - https://cookbook.openai.com/
   - https://platform.openai.com/settings/organization/general
   - https://platform.openai.com/settings/organization/general
     ```
     OPENAI_API_KEY=tu_clave_api
     ```

4. Inicia el servidor:
   ```bash
   python app.py
   ```

5. Accede a la aplicación desde tu navegador en [http://localhost:5000](http://localhost:5000).

---

# Instrucciones para levantar el Docker

## Prerrequisitos

Asegúrate de que tienes Docker y Docker Compose instalados en tu máquina:

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)

---

## Pasos rápidos para levantar el proyecto

### 1. **Construir y correr el contenedor**

Desde la raíz del proyecto (donde están el `Dockerfile` y `docker-compose.yml`), ejecuta este comando:

```bash
docker-compose up -d
```

Este comando:
- Construirá la imagen Docker automáticamente.
- Levantará el contenedor y lo ejecutará en segundo plano.

---

### 2. **Acceder a la aplicación**

- Una vez levantado el contenedor, abre tu navegador y ve a:  
  **[http://localhost](http://localhost)**

---

### 3. **Detener el contenedor**

Para detener el contenedor, utiliza este comando:

```bash
docker-compose down
```

---

### 4. **Reiniciar el contenedor con cambios**

Si realizas modificaciones al código, reconstruye y reinicia el contenedor con:

```bash
docker-compose up -d --build
```

---

## Uso

1. Selecciona el rango de IP o dominio a analizar.
2. Configura las opciones de escaneo (puertos específicos, velocidad, etc.).
3. Ejecuta el escaneo y revisa los resultados.
4. Genera reportes detallados con un clic.

---



