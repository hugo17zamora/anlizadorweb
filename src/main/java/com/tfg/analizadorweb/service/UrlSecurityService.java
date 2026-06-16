package com.tfg.analizadorweb.service;

//Framework Spring Boot
import org.springframework.stereotype.Service;
//Establecer conexiones HTTPS   
import javax.net.ssl.HttpsURLConnection;
//Crear socket SSL/TLS para el handshake        
import javax.net.ssl.SSLSocket;                 
import javax.net.ssl.SSLSocketFactory;          
import javax.net.ssl.SSLSession;
//Leer datos recibidos desde conexiones de red
import java.io.BufferedReader;
import java.io.InputStreamReader;
//Trabajar con URLs, direcciones IP y sockets
import java.net.InetAddress;
import java.net.Socket;
import java.net.URL;   
import java.net.UnknownHostException;
//Trabajar con certificados digitales
import java.security.cert.Certificate;
import java.security.cert.X509Certificate; 
//Gestionar fechas
import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
//Extraer información de CA
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
//Trabajar con listas y mapas
import java.util.List;
import java.util.Map;

@Service
public class UrlSecurityService{
    //Método auxiliar - Crear una conexión HTTPS 
    private HttpsURLConnection crearConexion(String url) throws Exception{
        //Crear objeto URL
        URL u = new URL(url.trim());
        //Abrir conexión HTTPS
        HttpsURLConnection connection = (HttpsURLConnection) u.openConnection();
        //Configurar conexión
        connection.setInstanceFollowRedirects(true);
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        //Iniciar conexión
        connection.connect();
        return connection;
    }

    //Método auxiliar - Obtener el certificado principal del servidor
    private X509Certificate obtenerCertificado(String url) throws Exception{
        //Crear conexión reutilizando método anterior
        HttpsURLConnection connection = crearConexion(url);
        //Obtener lista de certificados
        Certificate[] certificados = connection.getServerCertificates();
        //Devolver el primero (certificado principal) en formato X509Certificate (estándar)
        return (X509Certificate) certificados[0];
    }

    //Bloque A - Uso de HTTPS
    public String usoHttps(String url){
        try{
            //Crear objeto URL para analizar protocolo
            URL u = new URL(url.trim());
            //Comprobar si protocolo es HTTPS
            boolean tiene = u.getProtocol().equalsIgnoreCase("https");
            //Si tiene devolver Sí, si no tiene devolver No
            return tiene ? "Sí" : "No";
        }catch(Exception e){
            return "Error al comprobar si usa HTTPS";
        }
    }

    //Bloque A - Estado del certificado
    public String esValido(String url){
        try{
            //Obtener certificado usando método reutilizable
            X509Certificate cert = obtenerCertificado(url);
            //Comprobar validez (fecha)
            cert.checkValidity();
            //Si no salta excepción (ya es válido y no está caducado) devolver Sí
            return "Sí";
        }catch(java.security.cert.CertificateExpiredException e){
            return "No (Caducado)";
        }catch(java.security.cert.CertificateNotYetValidException e){
            return "No (Aún no es válido)";
        }catch(Exception e){
            return "Error al comprobar si el certificado es válido";
        }
    }

    //Bloque A - Certificado autofirmado
    public String autofirmado(String url){
        try{
            //Obtener certificado
            X509Certificate cert = obtenerCertificado(url);
            //Comparar Issuer y Subject
            boolean esAutofirmado = cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
            //Si coinciden, devolver Sí, si son diferentes, devolver No
            return esAutofirmado ? "Sí" : "No";
        }catch(Exception e){
            return "Error al comprobar si es autofirmado";
        }
    }

    //Bloque A - Autoridad de Certificación
    public String comprobarCA(String url){
        try{
            //Obtener certificado
            X509Certificate cert = obtenerCertificado(url);
            //Obtener Issuer
            String issuer = cert.getIssuerX500Principal().getName();
            //caName será donde guardaremos el nombre de la CA
            String caName = "Desconocida";
            //Extraer campo Organization (O)
            LdapName ldap = new LdapName(issuer);
            for(Rdn rdn : ldap.getRdns()){
                if("O".equalsIgnoreCase(rdn.getType())){
                    caName = rdn.getValue().toString().trim();
                    break;
                }
            }
            //Clasificar CA
            String caLower = caName.toLowerCase();
            if(caLower.contains("digicert") || caLower.contains("let's encrypt") || caLower.contains("globalsign") || 
                caLower.contains("sectigo") || caLower.contains("godaddy") || caLower.contains("entrust") || 
                caLower.contains("geotrust") || caLower.contains("thawte") || caLower.contains("google")){
                //Si coincide con alguna de las anteriores, devolver confiable
                return caName + " - Confiable";
            }else if(caLower.contains("actalis") || caLower.contains("buypass") || caLower.contains("harica") || 
                    caLower.contains("amazon") || caLower.contains("apple")){
                //Si coincide con alguna de las anteriores, devolver Poco común        
                return caName + " - Poco común";
            }else{
                //Si no coincide con ninguna, devolver desconocida
                return caName + " - Desconocida";
            }
        }catch(Exception e){
            return "Error al comprobar CA";
        }
    }

    //Bloque A - Protocolo TLS utilizado
    public String comprobarProtocoloTLS(String url){
        try{
            //Crear objeto URL
            URL u = new URL(url);
            //Extraer host
            String host = u.getHost();
            //Puerto estandar para comunicaciones Https
            int port = 443;
            //Crear socket SSL
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
            //Iniciar handshake
            socket.startHandshake();
            SSLSession session = socket.getSession();
            String protocolo = session.getProtocol();
            //Cerrar socket
            socket.close();
            //Clasificar
            if(protocolo.equals("TLSv1.3") || protocolo.equals("TLSv1.2")){
                //Si coinide con alguno de los anteriores, devolver Seguro
                return protocolo + " - Seguro";
            }else{
                //Si no coincide, devolver Inseguro
                return protocolo + " - Inseguro";
            }
        }catch(Exception e){
            return "Error al comprobar TLS";
        }
    }

    //Bloque B - Content Security Policy 
    public String comprobarCSP(String url){
        try{
            //Crear la conexión HTTPS usando el método reutilizable
            HttpsURLConnection connection = crearConexion(url);
            //Leer cabeceras
            String csp = connection.getHeaderField("Content-Security-Policy");
            String cspReportOnly = connection.getHeaderField("Content-Security-Policy-Report-Only");
            //Comprobar si alguna de las dos cabeceras está presente
            if((csp != null && !csp.isEmpty()) || (cspReportOnly != null && !cspReportOnly.isEmpty())){
                return "Sí";
            }else{
                return "No";
            }
        }catch(Exception e){
            return "Error al comprobar CSP";
        }
    }

    //Bloque B - X-Frame-Options
    public String comprobarXFrameOptions(String url){
        try{
            //Crear la conexión HTTPS reutilizable
            HttpsURLConnection connection = crearConexion(url);
            //Leer cabecera X-Frame-Options
            String xFrame = connection.getHeaderField("X-Frame-Options");
            //Comprobar si existe la cabecera
            if(xFrame != null && !xFrame.isEmpty()){
                //Normalizar texto
                xFrame = xFrame.trim().toUpperCase();
                //Comprobar
                if(xFrame.equals("DENY") || xFrame.equals("SAMEORIGIN")){
                    return xFrame + " - Seguro";
                }else{
                    return "Inseguro";
                }
            }else{
                return "Cabecera no detectada";
            }
        }catch(Exception e){
            return "Error al comprobar X-Frame-Options";
        }
    }

    //Bloque B - X-Content-Type-Options
    public String comprobarXContentTypeOptions(String url){
        try{
            //Crear la conexión HTTPS reutilizable
            HttpsURLConnection connection = crearConexion(url);
            //Leer cabecera X-Content-Type-Options
            String xContentType = connection.getHeaderField("X-Content-Type-Options");
            //Comprobar si existe
            if(xContentType != null && !xContentType.isEmpty()){
                //Normalizar texto
                xContentType = xContentType.trim().toLowerCase();
                //Comprobar
                if(xContentType.equals("nosniff")){
                    return xContentType + " - Seguro";
                }else{
                    return "Inseguro";
                }
            }else{
                return "Cabecera no detectada";
            }
        }catch(Exception e){
            return "Error al comprobar X-Content-Type-Options";
        }
    }

    //Bloque B - Referrer-Policy
    public String comprobarReferrerPolicy(String url){
        try{
            //Crear la conexión HTTPS reutilizable
            HttpsURLConnection connection = crearConexion(url);
            //Leer cabecera Referrer-Policy
            String referrer = connection.getHeaderField("Referrer-Policy");
            //Comprobar si existe
            if(referrer != null && !referrer.isEmpty()){
                //Normalizar texto
                referrer = referrer.trim().toLowerCase();
                //Clasificar 
                if(referrer.contains("no-referrer") ||  referrer.contains("strict-origin")){
                    return referrer + " - Seguro";
                }else if(referrer.contains("origin")){
                    return referrer + " - Intermedio";
                }else{
                    return "Inseguro";
                }
            }else{
                return "Cabecera no detectada";
            }
        }catch(Exception e){
            return "Error al comprobar Referrer-Policy";
        }
    }

    //Bloque B - Permissions-Policy
    public String comprobarPermissionsPolicy(String url){
        try{
            //Crear la conexión HTTPS reutilizable
            HttpsURLConnection connection = crearConexion(url);
            //Leer cabecera Permissions-Policy
            String policyHeader = connection.getHeaderField("Permissions-Policy");
            //Comprobar si existe
            if(policyHeader != null && !policyHeader.isEmpty()){
                //Normalizar texto
                policyHeader = policyHeader.toLowerCase();
                //Lista de permisos considerados sensibles
                String[] permisos = {"camera","microphone","geolocation", "payment","clipboard-read","usb"};
                //Contador
                int count = 0;
                //Contar cuántos permisos sensibles aparecen habilitados y no bloqueados
                for(String permiso : permisos){
                    //Ejemplo permiso seguro: camera=()
                    boolean bloqueado = policyHeader.contains(permiso + "=()");
                    //Ejemplos permiso habilitado: camera=*, camera=(self)
                    boolean aparece = policyHeader.contains(permiso + "=");
                    if(aparece && !bloqueado){
                        count++;
                    }
                }
                //Clasificar
                if(count <= 2){
                    return "Seguro, " + count + " permiso/s sensibles habilitados";
                }else if(count <= 4){
                    return "Intermedio, " + count + " permisos sensibles habilitados";
                }else{
                    return "Inseguro, " + count + " permisos sensibles habilitados";
                }
            }else{
                return "Cabecera no detectada";
            }
        }catch(Exception e){
            return "Error al comprobar Permissions-Policy";
        }
    }

    //Bloque C - DNSSEC
    public String comprobarDnssec(String url){
        try{
            //Crear objeto URL
            URL u = new URL(url);
            //Extraer dominio
            String dominio = u.getHost();
            //Construir consulta a Google Public DNS para obtener registros DNSKEY
            URL consulta = new URL("https://dns.google/resolve?name=" + dominio + "&type=DNSKEY");
            //Abrir conexión HTTPS con el servicio de resolución DNS
            HttpsURLConnection connection = (HttpsURLConnection) consulta.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            //Leer respuesta devuelta por el servidor DNS
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String linea;
            StringBuilder respuesta = new StringBuilder();
            //Concatenar todo el contenido de la respuesta
            while((linea = in.readLine()) != null){
                respuesta.append(linea);
            }
            in.close();
            //Convertir la respuesta a JSON
            String json = respuesta.toString();
            //En DNS, el tipo 48 corresponde a registros DNSKEY, si aparece, significa que el dominio tiene DNSSEC habilitado
            if(json.contains("\"type\":48")){
                return "Sí";
            }else{
                return "No";
            }
        }catch(Exception e){
            return "Error al comprobar DNSSEC";
        }
    }

    //Bloque C - Dominio en DNS públicos de confianza
    public String comprobarDns(String url){
        try{
            //Crear objeto URL
            URL u = new URL(url);
            //Extraer dominio
            String dominio = u.getHost();
            //Lista de DNS públicos de confianza
            String[] dnsServidores = {
                "8.8.8.8", "8.8.4.4",              //Google
                "1.1.1.1",                         //Cloudflare
                "208.67.222.222", "208.67.220.220",//OpenDNS
                "9.9.9.9", "149.112.112.112"       //Quad9
            };
            //Contador de respuestas válidas
            int respuestasValidas = 0;
            //Intentar resolver dominio
            for(String dns : dnsServidores){
                try{
                    InetAddress direccion = InetAddress.getByName(dominio);
                    if(direccion != null){
                        respuestasValidas++;
                    }
                }catch(Exception ignored){}
            }
            //Clasificar resultado
            if(respuestasValidas >= 5){
                return "Seguro";
            }else if(respuestasValidas >= 3){
                return "Intermedio";
            }else{
                return "Inseguro";
            }
        }catch(Exception e){
            return "Error al comprobar DNS públicos";
        }
    }

    //Bloque C - Antigüedad del dominio
    public String comprobarAntiguo(String url){
        try{
            //Crear objeto URL
            URL u = new URL(url);
            //Extraer dominio
            String dominio = u.getHost();
            //Conectar con servidor WHOIS (puerto 43)
            Socket socket = new Socket("whois.verisign-grs.com", 43);
            //Enviar dominio consultado
            socket.getOutputStream().write((dominio + "\r\n").getBytes());
            //Leer respuesta WHOIS
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String linea;
            LocalDate fechaCreacion = null;
            //Buscar línea de fecha de creación
            while((linea = in.readLine()) != null){
                if(linea.toLowerCase().contains("creation date")){
                    String fecha = linea.split(":")[1].trim().substring(0,10);
                    fechaCreacion = LocalDate.parse(fecha, DateTimeFormatter.ISO_DATE);
                    break;
                }
            }
            //Cerrar conexión
            socket.close();
            //Si se obtuvo fecha, calcular antigüedad
            if(fechaCreacion != null){
                Period edad = Period.between(fechaCreacion, LocalDate.now());
                int años = edad.getYears();
                //Clasificar según años
                if(años >= 5){
                    return años + " años - Seguro";
                }else if(años >= 1){
                    return años + " años - Intermedio";
                }else{
                    return años + " años - Inseguro";
                }
            }
            return "No se pudo determinar antigüedad";
        }catch(Exception e){
            return "Error al comprobar antigüedad del dominio";
        }
    }

    //Bloque C - Listas negras
    public String comprobarLn(String url){
        try{
            //Crear objeto URL
            URL u = new URL(url);
            //Extraer dominio
            String dominio = u.getHost();
            //Obtener dirección IP del dominio
            InetAddress ip = InetAddress.getByName(dominio);
            //Invertir IP para consulta DNSBL
            String[] partes = ip.getHostAddress().split("\\.");
            String ipInvertida = partes[3] + "." + partes[2] + "." + partes[1] + "." + partes[0];
            //Lista de DNSBL conocidas
            String[] dnsbl = {"zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net"};
            //Comprobar cada lista negra
            for(String lista : dnsbl){
                try{
                    InetAddress.getByName(ipInvertida + "." + lista);
                    return "Inseguro (Aparece en lista negra: " + lista + ")";
                }catch(UnknownHostException ignored){}
            }
            //Si no aparece en ninguna
            return "Seguro";
        }catch(Exception e){
            return "Error al comprobar listas negras";
        }
    }

    //Bloque D - Página de Política de Privacidad
    public String comprobarPp(String url){
        try{
            //Crear conexión HTTPS 
            HttpsURLConnection connection = crearConexion(url);
            //Leer contenido HTML
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String linea;
            StringBuilder contenido = new StringBuilder();
            //Concatenar contenido
            while((linea = in.readLine()) != null){
                contenido.append(linea.toLowerCase());
            }
            //Buscar palabras clave relacionadas
            if(contenido.toString().contains("política de privacidad") || contenido.toString().contains("privacy policy")){
                return "Sí";
            }else{
                return "No";
            }
        }catch(Exception e){
            return "Error al comprobar política de privacidad";
        }
    }


    //Bloque D - Aviso o Política de Cookies
    public String comprobarCookies(String url){
        try{
            //Crear conexión HTTPS 
            HttpsURLConnection connection = crearConexion(url);
            //Leer contenido HTML
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String linea;
            StringBuilder contenido = new StringBuilder();
            while((linea = in.readLine()) != null){
                contenido.append(linea.toLowerCase());
            }
            //Buscar términos relacionados con cookies
            if(contenido.toString().contains("cookies") && (contenido.toString().contains("aceptar") || contenido.toString().contains("rechazar"))){
                return "Sí";
            }else{
                return "No";
            }
        }catch(Exception e){
            return "Error al comprobar aviso de cookies";
        }
    }


    //Bloque D - Términos y condiciones / Aviso legal
    public String comprobarAviso(String url){
        try{
            //Crear conexión HTTPS 
            HttpsURLConnection connection = crearConexion(url);
            //Leer contenido HTML
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String linea;
            StringBuilder contenido = new StringBuilder();
            while((linea = in.readLine()) != null){
                contenido.append(linea.toLowerCase());
            }
            //Buscar términos legales
            if(contenido.toString().contains("términos y condiciones") || contenido.toString().contains("aviso legal") || contenido.toString().contains("terms and conditions")){
                return "Sí";
            }else{
                return "No";
            }
        }catch(Exception e){
            return "Error al comprobar aviso legal";
        }
    }

    //Bloque D - Información de contacto
    public String comprobarContacto(String url){
        try{
            //Crear conexión HTTPS 
            HttpsURLConnection connection = crearConexion(url);
            //Leer contenido HTML
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String linea;
            StringBuilder contenido = new StringBuilder();
            while((linea = in.readLine()) != null){
                contenido.append(linea.toLowerCase());
            }
            //Buscar patrones básicos de contacto
            if(contenido.toString().contains("contacto") || contenido.toString().contains("contact") || contenido.toString().contains("@")){
                return "Sí";
            }else{
                return "No";
            }
        }catch(Exception e){
            return "Error al comprobar información de contacto";
        }
    }

    //Bloque D - Atributos de seguridad en Cookies
    public String comprobarAtCookies(String url){
        try{
            //Crear conexión HTTPS 
            HttpsURLConnection connection = crearConexion(url);
            //Obtener cabeceras
            Map<String, List<String>> headers = connection.getHeaderFields();
            boolean secure = false;
            boolean httpOnly = false;
            boolean sameSite = false;
            //Buscar cabeceras Set-Cookie
            List<String> cookies = headers.get("Set-Cookie");
            if(cookies != null){
                for(String cookie : cookies){
                    String lower = cookie.toLowerCase();
                    if(lower.contains("secure")){
                        secure = true;
                    }
                    if(lower.contains("httponly")){
                        httpOnly = true;
                    }
                    if(lower.contains("samesite")){
                        sameSite = true;
                    }
                }
                //Clasificar resultado
                if(secure && httpOnly && sameSite){
                    return "Secure, HttpOnly y SameSite - Seguro";
                }else if(secure || httpOnly || sameSite){
                    return "Secure, HttpOnly o SameSite - Intermedio";
                }else{
                    return "Inseguro";
                }
            }else{
                return "No se detectaron cookies";
            }
        }catch(Exception e){
            return "Error al comprobar atributos de cookies";
        }
    }
}