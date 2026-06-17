package com.tfg.analizadorweb.controller;
//Modelo que almacena todos los resultados del análisis
import com.tfg.analizadorweb.model.ResultadoAnalisis;
//Sevicios
import com.tfg.analizadorweb.service.PdfService;
import com.tfg.analizadorweb.service.UrlSecurityService;
//Framework Spring Boot
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;
//Almacenar y recuperar datos de la sesión
import jakarta.servlet.http.HttpSession;

@Controller
public class HomeController{
    //Servicio que realiza todas las comprobaciones 
    private final UrlSecurityService urlservice;
    //Servicio encargado de generar el PDF del informe
    private final PdfService pdfService;
    //Constructor 
    public HomeController(UrlSecurityService urlservice, PdfService pdfService){
        this.urlservice = urlservice;
        this.pdfService = pdfService;
    }
    //Página principal
    @GetMapping("/")
    public String home(){
        //Devuelve la vista index.html
        return "index";
    }

    //Endpoint que procesa el formulario de análisis
    @PostMapping("/analizar")
    public String analizar(@RequestParam String url, Model model, HttpSession session){
        //Validar que la URL
        if(!esUrlValida(url)){
            model.addAttribute("error", "La URL no es válida o el dominio no está disponible.");
            return "index";
        }
        //Realizar el análisis
        ResultadoAnalisis r = realizarAnalisis(url);
        //Si el análisis sale mal
        if(r == null){
            model.addAttribute("error", "Se ha producido un error durante el análisis.");
            return "index";
        }
        //Guardar resultado
        session.setAttribute("resultadoAnalisis", r);
        
        //Pasar datos básicos a la vista
        model.addAttribute("url", r.getUrl());
        model.addAttribute("puntuacion", r.getPuntuacion() + "/100");

        return "result";
    }

    //Endpoint que muestra el informe completo
    @GetMapping("/informe")
    public String verInforme(Model model, HttpSession session){
        //Recuperar el análisis guardado en sesión
        ResultadoAnalisis r = (ResultadoAnalisis) session.getAttribute("resultadoAnalisis");
        //Si no se ha realizado análisis antes
        if(r == null){
            model.addAttribute("error", "Primero debes realizar un análisis.");
            return "index";
        }

        //Cargar todos los datos del análisis en el modelo
        cargarModeloInforme(model, r);

        return "informe";
    }

    //Endpoint que genera y descarga el PDF
    @GetMapping("/pdf")
    public ResponseEntity<byte[]> descargarPdf(HttpSession session){
        //Recuperar el análisis guardado en sesión
        ResultadoAnalisis r = (ResultadoAnalisis) session.getAttribute("resultadoAnalisis");
        //Si no se ha realizado análisis antes
        if(r == null){
            return ResponseEntity
                    .badRequest()
                    .body("Primero debes realizar un análisis.".getBytes());
        }
        //Generar PDF con todos los datos del análisis
        byte[] pdf = pdfService.generarInforme(
                r.getUrl(),
                r.getPuntuacion(),
                //Bloque A
                r.getHttps(),
                r.getCertificado(),
                r.getAutofirmado(),
                r.getCa(),
                r.getTls(),
                //Bloque B
                r.getCsp(),
                r.getXFrame(),
                r.getXContent(),
                r.getReferrer(),
                r.getPermissions(),
                //Bloque C
                r.getDnssec(),
                r.getDns(),
                r.getAntiguo(),
                r.getLn(),
                //Bloque D
                r.getPp(),
                r.getCookies(),
                r.getAviso(),
                r.getContacto(),
                r.getAtCookies()
        );
        //Configurar respuesta HTTP para descargar archivo
        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=informe.pdf")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }

    //Endpoint para volver al resultado
    @GetMapping("/resultado")
    public String resultado(HttpSession session, Model model){
        //Recuperar el análisis guardado en sesión
        ResultadoAnalisis r = (ResultadoAnalisis) session.getAttribute("resultadoAnalisis");
        //Si no se ha realizado análisis antes
        if(r == null){
            model.addAttribute("error", "Primero debes realizar un análisis.");
            return "index";
        }
        //Cargar todos los datos del análisis en el modelo
        model.addAttribute("url", r.getUrl());
        model.addAttribute("puntuacion", r.getPuntuacion() + "/100");

        return "result";
    }

    // Método auxiliar para cargar todos los datos en informe.html
    private void cargarModeloInforme(Model model, ResultadoAnalisis r){

        //Datos generales
        model.addAttribute("url", r.getUrl());
        model.addAttribute("puntuacion", r.getPuntuacion() + "/100");

        //Bloque A 
        model.addAttribute("https", r.getHttps());
        model.addAttribute("certificado", r.getCertificado());
        model.addAttribute("autofirmado", r.getAutofirmado());
        model.addAttribute("ca", r.getCa());
        model.addAttribute("tls", r.getTls());

        //Bloque B 
        model.addAttribute("csp", r.getCsp());
        model.addAttribute("xFrame", r.getXFrame());
        model.addAttribute("xContent", r.getXContent());
        model.addAttribute("referrer", r.getReferrer());
        model.addAttribute("permissions", r.getPermissions());

        //Bloque C 
        model.addAttribute("dnssec", r.getDnssec());
        model.addAttribute("dns", r.getDns());
        model.addAttribute("antiguo", r.getAntiguo());
        model.addAttribute("ln", r.getLn());

        //Bloque D 
        model.addAttribute("pp", r.getPp());
        model.addAttribute("cookies", r.getCookies());
        model.addAttribute("aviso", r.getAviso());
        model.addAttribute("contacto", r.getContacto());
        model.addAttribute("atCookies", r.getAtCookies());
    }

    //Método de análisis
    private ResultadoAnalisis realizarAnalisis(String url){
        try{
            //Bloque A
            String https = urlservice.usoHttps(url);
            String certificado = urlservice.esValido(url);
            String autofirmado = urlservice.autofirmado(url);
            String ca = urlservice.comprobarCA(url);
            String tls = urlservice.comprobarProtocoloTLS(url);
            //Bloque B
            String csp = urlservice.comprobarCSP(url);
            String xFrame = urlservice.comprobarXFrameOptions(url);
            String xContent = urlservice.comprobarXContentTypeOptions(url);
            String referrer = urlservice.comprobarReferrerPolicy(url);
            String permissions = urlservice.comprobarPermissionsPolicy(url);
            //Bloque C
            String dnssec = urlservice.comprobarDnssec(url);
            String dns = urlservice.comprobarDns(url);
            String antiguo = urlservice.comprobarAntiguo(url);
            String ln = urlservice.comprobarLn(url);
            //Bloque D
            String pp = urlservice.comprobarPp(url);
            String cookies = urlservice.comprobarCookies(url);
            String aviso = urlservice.comprobarAviso(url);
            String contacto = urlservice.comprobarContacto(url);
            String atCookies = urlservice.comprobarAtCookies(url);

            //Calcular puntuación
            int puntuacion = 0;
            // Bloque A
            if(https.contains("Sí")) puntuacion += 12;
            if(certificado.contains("Sí")) puntuacion += 8;
            if(autofirmado.contains("No")) puntuacion += 6;
            if(ca.contains("Confiable")) puntuacion += 5;
            else if(ca.contains("Poco común")) puntuacion += 2;
            if(tls.contains("Seguro")) puntuacion += 4;
            // Bloque B
            if(csp.contains("Sí")) puntuacion += 12;
            if(xFrame.contains("Seguro")) puntuacion += 6;
            if(xContent.contains("Seguro")) puntuacion += 6;
            if(referrer.contains("Seguro")) puntuacion += 6;
            else if(referrer.contains("Intermedio")) puntuacion += 3;
            if(permissions.contains("Seguro")) puntuacion += 5;
            else if(permissions.contains("Intermedio")) puntuacion += 2;
            //Bloque C
            if(dnssec.contains("Sí")) puntuacion += 5;
            if(dns.contains("Seguro")) puntuacion += 4;
            else if(dns.contains("Intermedio")) puntuacion += 2;
            if(antiguo.contains("Seguro")) puntuacion += 3;
            else if(antiguo.contains("Intermedio")) puntuacion += 2;
            if(ln.contains("Seguro")) puntuacion += 3;
            //Bloque D
            if(pp.contains("Sí")) puntuacion += 4;
            if(cookies.contains("Sí")) puntuacion += 3;
            if(aviso.contains("Sí")) puntuacion += 3;
            if(contacto.contains("Sí")) puntuacion += 2;
            if(atCookies.contains("Seguro")) puntuacion += 3;
            else if(atCookies.contains("Intermedio")) puntuacion += 2;

            //Crear objeto resultado con todos los datos
            return new ResultadoAnalisis(
                    url, puntuacion,
                    //Bloque A
                    https, certificado, autofirmado,ca, tls,
                    //Bloque B
                    csp, xFrame, xContent, referrer, permissions,
                    //Bloque C
                    dnssec, dns, antiguo, ln,
                    //Bloque D
                    pp, cookies, aviso, contacto, atCookies
            );
        }catch(Exception e){
            return null;
        }
    }

    //Validación de URL 
    private boolean esUrlValida(String url){
        //Comprobar que no sea null ni esté vacía
        if(url == null || url.isBlank()){
            return false;
        }
        try{
            //Crear objeto URL para validar estructura
            java.net.URL u = new java.net.URL(url.trim());
            //Validar que el protocolo sea http o https
            String protocolo = u.getProtocol();
            if(!protocolo.equalsIgnoreCase("http") && !protocolo.equalsIgnoreCase("https")){
                return false;
            }
            //Validar que exista un host válido
            String host = u.getHost();
            if(host == null || host.isBlank() || !host.contains(".")){
                return false;
            }
            return true;
        }catch(Exception e){
            //Si ocurre cualquier error, URL no válida
            return false;
        }
    }

    //Páginas informativas
    @GetMapping("/seguridad-conexion")
    public String seguridadConexion(){
        return "seguridad-conexion";
    }

    @GetMapping("/seguridad-servidor")
    public String seguridadServidor(){
        return "seguridad-servidor";
    }

    @GetMapping("/dominio-dns")
    public String dominioDns(){
        return "dominio-dns";
    }

    @GetMapping("/legal-privacidad")
    public String legalPrivacidad(){
        return "legal-privacidad";
    }
}
