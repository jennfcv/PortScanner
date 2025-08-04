from flask import Flask, render_template, request, jsonify
import yaml
import openai
import requests
import ssl
import socket
import os
import dns.resolver
import concurrent.futures
from datetime import datetime

# Crear la aplicación Flask
app = Flask(__name__)

# Diccionario de servicios comunes
PORT_SERVICES = {
    20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet', 
    25: 'SMTP', 53: 'DNS', 67: 'DHCP Server', 68: 'DHCP Client',
    69: 'TFTP', 80: 'HTTP', 110: 'POP3', 111: 'RPCbind', 
    123: 'NTP', 135: 'MS RPC', 137: 'NetBIOS', 138: 'NetBIOS',
    139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP Trap',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    514: 'Syslog', 587: 'SMTP Submission', 631: 'IPP', 636: 'LDAPS',
    993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN',
    1433: 'MS SQL', 1521: 'Oracle DB', 1723: 'PPTP', 1883: 'MQTT',
    1900: 'UPnP', 2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel SSL',
    2086: 'WHM', 2087: 'WHM SSL', 2095: 'Webmail', 2096: 'Webmail SSL',
    2181: 'ZooKeeper', 2375: 'Docker', 2376: 'Docker SSL',
    3000: 'Node.js', 3306: 'MySQL', 3389: 'RDP', 4333: 'mSQL',
    4444: 'Metasploit', 4567: 'Sinatra', 4711: 'FileZilla Admin',
    4712: 'FileZilla Admin', 4848: 'GlassFish', 5000: 'UPnP',
    5432: 'PostgreSQL', 5601: 'Kibana', 5672: 'AMQP', 5900: 'VNC',
    5938: 'TeamViewer', 5984: 'CouchDB', 6379: 'Redis',
    6666: 'IRC', 8000: 'HTTP Alt', 8008: 'HTTP Alt', 8080: 'HTTP Proxy',
    8081: 'HTTP Proxy', 8443: 'HTTPS Alt', 8888: 'HTTP Alt',
    9000: 'PHP-FPM', 9042: 'Cassandra', 9090: 'CockroachDB',
    9100: 'JetDirect', 9200: 'Elasticsearch', 9300: 'Elasticsearch',
    11211: 'Memcached', 27017: 'MongoDB', 27018: 'MongoDB',
    28017: 'MongoDB HTTP', 50000: 'SAP', 50070: 'HDFS'
}

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
config = {
    'OPENAI_API_KEY': os.getenv('OPENAI_API_KEY')
}
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

def get_service_name(port):
    return PORT_SERVICES.get(port, 'Desconocido')

def check_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((target, port))
        
        if result == 0:
            service_info = get_service_info(sock, port)
            sock.close()
            
            return {
                'port': port,
                'name': get_service_name(port),
                'product': service_info.get('product', 'Desconocido'),
                'version': service_info.get('version', 'Desconocido'),
                'extrainfo': service_info.get('extrainfo', 'Detectado con escaneo básico')
            }
        sock.close()
    except Exception:
        return None
    return None

def get_service_info(sock, port):
    """Intenta obtener información del servicio"""
    try:
        sock.settimeout(2.0)
        
        if port in [21, 22, 25, 80, 110, 143, 443, 587, 993, 995, 3306, 3389, 5432]:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            info = {'extrainfo': f"Banner: {banner[:100]}"}
            
            if port == 22 and 'SSH' in banner:
                info['product'] = 'OpenSSH'
                if 'OpenSSH' in banner:
                    version = banner.split('OpenSSH_')[1].split()[0]
                    info['version'] = version.split('-')[0]
            
            elif port == 80 or port == 443:
                if 'Apache' in banner or 'Server:' in banner:
                    info['product'] = 'Apache'
                    if 'Server:' in banner:
                        version = banner.split('Server:')[1].split()[0]
                        info['version'] = version
                
                elif 'nginx' in banner.lower():
                    info['product'] = 'nginx'
                    if 'nginx/' in banner.lower():
                        version = banner.lower().split('nginx/')[1].split()[0]
                        info['version'] = version
            
            elif port == 3306:
                if 'MySQL' in banner:
                    info['product'] = 'MySQL'
                    version_part = banner.split('5.')
                    if len(version_part) > 1:
                        info['version'] = '5.' + version_part[1][:3]
            
            return info
            
    except Exception:
        pass
    
    return {'product': 'Desconocido', 'version': 'Desconocido', 'extrainfo': 'No se pudo obtener banner'}

def simple_port_scan(target, scan_type="default"):
    # Definir puertos según el tipo de escaneo
    if scan_type == "fast":
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                         993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080]
    elif scan_type == "tcp_syn":
        ports_to_scan = list(PORT_SERVICES.keys())
    elif scan_type == "service_detection":
        ports_to_scan = [21, 22, 25, 53, 80, 110, 143, 389, 443, 445,
                         587, 993, 995, 1433, 1521, 2049, 3306, 3389,
                         5432, 5900, 5984, 6379, 8000, 8080, 8443, 9200,
                         27017, 50000]
    else:  # "default" - Análisis exhaustivo
        ports_to_scan = list(PORT_SERVICES.keys()) + [
            8081, 8888, 9000, 9042, 9090, 11211, 27018, 28017, 50070
        ]

    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {
            executor.submit(check_port, target, port): port 
            for port in ports_to_scan
        }
        
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception:
                continue
    
    open_ports.sort(key=lambda x: x['port'])
    return open_ports

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    scan_type = request.form.get('scan_type')

    if not target:
        print("[ERROR] No se ingresó un objetivo para escanear.")
        return render_template('index.html', error="Por favor, ingresa un objetivo válido.")

    print(f"[INFO] Iniciando escaneo para el objetivo: {target} con tipo: {scan_type}")

    try:
        # Escaneos tradicionales reemplazados
        if scan_type in ["default", "fast", "tcp_syn", "service_detection"]:
            open_ports = simple_port_scan(target, scan_type)
            return render_template('results.html', target=target, open_ports=open_ports, scan_type=scan_type)
        
        # Escaneos web
        elif scan_type == "ssl":
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