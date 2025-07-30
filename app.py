from flask import Flask, render_template, request, jsonify
import nmap
import yaml
import openai
from datetime import datetime
import requests
import ssl
import socket
import dns.resolver

# Crear la aplicación Flask
app = Flask(__name__)

# Cargar configuración desde un archivo YAML
def load_config():
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
        print("[INFO] Configuración cargada correctamente.")
        return config
    except FileNotFoundError:
        print("[ERROR] El archivo 'config.yaml' no existe. Asegúrate de crearlo con las configuraciones necesarias.")
    except Exception as e:
        print(f"[ERROR] Error al cargar el archivo de configuración: {e}")
    return {}

# Cargar la configuración
config = load_config()

# Configurar la clave de la API de OpenAI
if 'OPENAI_API_KEY' in config:
    openai.api_key = config['OPENAI_API_KEY']
    openai.api_base = "https://api.openai.com/v1"  # Endpoint oficial de OpenAI
    print("[INFO] OpenAI API configurado correctamente.")
else:
    print("[WARNING] La clave API de OpenAI no está configurada.")

# Ruta principal
@app.route('/')
def home():
    print("[INFO] Acceso a la página principal.")
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    scan_type = request.form.get('scan_type')

    if not target:
        print("[ERROR] No se ingresó un objetivo para escanear.")
        return render_template('index.html', error="Por favor, ingresa un objetivo válido.")

    print(f"[INFO] Iniciando escaneo para el objetivo: {target} con tipo: {scan_type}")

    try:
        # --- Escaneos tradicionales con Nmap ---
        if scan_type in ["default", "fast", "tcp_syn", "service_detection", "os_detection", "udp"]:
            nm = nmap.PortScanner()

            scan_arguments = {
                "default": "-sS -sV -O -A",
                "fast": "-F",
                "tcp_syn": "-sS",
                "service_detection": "-sV",
                "os_detection": "-O",
                "udp": "-sU"
            }.get(scan_type, "-sS -sV -O -A")  # Valor por defecto

            results = nm.scan(hosts=target, arguments=scan_arguments)
            print(f"[INFO] Resultados del escaneo: {results}")

            open_ports = []

            scanned_hosts = results.get('scan', {})
            if scanned_hosts:
                scanned_host = next(iter(scanned_hosts.keys()))
                tcp_results = scanned_hosts.get(scanned_host, {}).get('tcp', {})

                for port, info in tcp_results.items():
                    if info.get('state') == 'open':
                        open_ports.append({
                            'port': port,
                            'name': info.get('name', 'N/A'),
                            'product': info.get('product', 'N/A'),
                            'version': info.get('version', 'N/A'),
                            'extrainfo': info.get('extrainfo', 'N/A')
                        })

            print(f"[INFO] Puertos abiertos detectados: {open_ports}")
            return render_template('results.html', target=target, open_ports=open_ports, scan_type=scan_type)

        # --- Escaneos de seguridad web (SSL, Headers, Subdomains, Technologies) ---
        else:
            if scan_type == "ssl":
                result = scan_ssl(target)
            elif scan_type == "headers":
                result = scan_headers(f"http://{target}")
            elif scan_type == "subdomains":
                result = find_subdomains(target)
            elif scan_type == "technologies":
                result = detect_technologies(f"http://{target}")
            else:
                result = {"error": "Tipo de análisis no reconocido."}

            print(f"[INFO] Resultados de {scan_type}: {result}")
            return render_template('results.html', target=target, scan_type=scan_type, result=result)

    except Exception as e:
        print(f"[ERROR] Error durante el análisis: {e}")
        return render_template('index.html', error=f"Error al realizar el escaneo: {str(e)}")


@app.route('/action', methods=['POST'])
def action():
    port = request.form.get('port')
    product = request.form.get('product')
    version = request.form.get('version')
    extra_info = request.form.get('extrainfo')

    print(f"[INFO] Acción recibida para el puerto {port} con producto {product}, versión {version}, extra: {extra_info}")

    advice = "La funcionalidad de generación de información no está disponible en este momento."
    risk_level = "Desconocido"

    if config.get('OPENAI_API_KEY'):
        try:
            solicitud = (
                f"Actúa como un analista de ciberseguridad. Analiza el puerto {port} detectando "
                f"riesgos, vulnerabilidades, amenazas conocidas del producto {product} "
                f"(versión {version}), y sugiere medidas de mitigación. "
                f"Información adicional: {extra_info}. Resume también el nivel de riesgo (Alto, Medio, Bajo)."
                "Proporciona la respuesta en formato markdown con encabezados claros."
            )

            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "Eres un experto en análisis de seguridad de redes."},
                    {"role": "user", "content": solicitud}
                ],
                temperature=0.3,
                max_tokens=800
            )

            print(f"[DEBUG] Respuesta de OpenAI: {response}")

            if response.choices:
                full_response = response.choices[0].message.content.strip()
                advice = full_response
                
                # Determinar nivel de riesgo
                if "alto" in full_response.lower():
                    risk_level = "Alto"
                elif "medio" in full_response.lower():
                    risk_level = "Medio"
                elif "bajo" in full_response.lower():
                    risk_level = "Bajo"
            else:
                advice = "No se recibió respuesta válida de OpenAI."

        except openai.error.AuthenticationError:
            error_msg = "Error de autenticación con OpenAI. Verifica tu API Key."
            print(f"[ERROR] {error_msg}")
            advice = error_msg
        except openai.error.RateLimitError:
            error_msg = "Límite de tasa excedido. Espera un momento o verifica tu plan."
            print(f"[ERROR] {error_msg}")
            advice = error_msg
        except Exception as e:
            error_msg = f"Error al conectar con OpenAI: {str(e)}"
            print(f"[ERROR] {error_msg}")
            advice = error_msg

    return render_template(
        'action.html', 
        port=port, 
        advice=advice, 
        product=product, 
        version=version, 
        extra_info=extra_info, 
        risk_level=risk_level
    )

@app.route('/recomendacion', methods=['POST'])
def recomendacion():
    tipo_analisis = request.form.get('tipo_analisis')
    resultados = request.form.get('resultados')

    if not resultados:
        return render_template('index.html', error="No se recibieron resultados para analizar.")

    if not config.get('OPENAI_API_KEY'):
        return render_template('recomendacion.html', 
                             tipo_analisis=tipo_analisis,
                             recomendacion="Error: No se configuró la API Key de OpenAI")

    try:
        prompt = f"""
        Actúa como un analista de ciberseguridad. Se realizó un análisis de tipo '{tipo_analisis}' 
        con los siguientes resultados: {resultados}. 
        
        Proporciona recomendaciones de seguridad específicas basadas en estos hallazgos. 
        Organiza tu respuesta en:
        1. Resumen de riesgos
        2. Recomendaciones técnicas
        3. Buenas prácticas
        """

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "Eres un experto en ciberseguridad que proporciona recomendaciones claras y prácticas."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.5,
            max_tokens=1000
        )

        if response.choices:
            recomendacion = response.choices[0].message.content.strip()
        else:
            recomendacion = "No se recibió respuesta válida de OpenAI."

    except Exception as e:
        recomendacion = f"Error al generar recomendación: {str(e)}"

    return render_template('recomendacion.html', 
                         tipo_analisis=tipo_analisis, 
                         recomendacion=recomendacion)

# --- Escaneo SSL ---
def scan_ssl(domain):
    context = ssl.create_default_context()
    ssl_info = {}
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_info['ssl_valid'] = True
                ssl_info['issuer'] = dict(x[0] for x in cert['issuer'])['organizationName']
                ssl_info['valid_from'] = cert['notBefore']
                ssl_info['valid_to'] = cert['notAfter']
    except Exception as e:
        ssl_info['ssl_valid'] = False
        ssl_info['error'] = str(e)
    return ssl_info

# --- Escaneo de Cabeceras HTTP ---
def scan_headers(url):
    headers_info = {}
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        for header in ['Content-Security-Policy', 'X-Frame-Options', 
                       'Strict-Transport-Security', 'X-Content-Type-Options', 
                       'Referrer-Policy']:
            headers_info[header] = headers.get(header, 'No encontrado')
    except Exception as e:
        headers_info['error'] = str(e)
    return headers_info

# --- Detección de Subdominios ---
def find_subdomains(domain):
    subdomains = []
    common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'blog']
    resolver = dns.resolver.Resolver()
    for sub in common_subs:
        try:
            full_domain = f"{sub}.{domain}"
            resolver.resolve(full_domain, 'A')
            subdomains.append(full_domain)
        except:
            continue
    return subdomains

# --- Detección de Tecnologías ---
def detect_technologies(url):
    tech_info = {}
    try:
        response = requests.get(url, timeout=5)
        tech_info['Server'] = response.headers.get('Server', 'No detectado')
        tech_info['X-Powered-By'] = response.headers.get('X-Powered-By', 'No detectado')
    except Exception as e:
        tech_info['error'] = str(e)
    return tech_info

if __name__ == '__main__':
    print("[INFO] Aplicación iniciada en modo depuración.")
    app.run(debug=True, host='0.0.0.0', port=5200)