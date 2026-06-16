package com.tfg.analizadorweb.service;

//Generación de PDF
import com.lowagie.text.*;
import com.lowagie.text.pdf.*;
//Framework Spring Boot
import org.springframework.stereotype.Service;
//Trabajar con colores
import java.awt.Color;
//Generar el PDF en memoria
import java.io.ByteArrayOutputStream;
//Gestionar fechas
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Service
public class PdfService{
    //Recibe todos los resultados del análisis y genera el PDF en formato byte[]
    public byte[] generarInforme(
            String url, int puntuacion,
            //Bloque A
            String https, String certificado, String autofirmado, String ca, String tls,
            //Bloque B
            String csp, String xFrame, String xContent, String referrer, String permissions,
            //Bloque C
            String dnssec, String dns, String antiguo, String ln,
            //Bloque D
            String pp, String cookies, String aviso, String contacto, String atCookies){
        try{
            //Crar PDF en tamaño A4 con márgenes
            Document document = new Document(PageSize.A4, 50, 50, 40, 40);
            //Guardar PDF en memoria
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            //Asociar con flujo de salida
            PdfWriter.getInstance(document, out);
            //Abrir documento
            document.open();
            //Definir fuentes que se usan en el informe
            Font fuenteTitulo = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 28, new Color(34, 197, 94));
            Font fuenteSubtitulo = FontFactory.getFont(FontFactory.HELVETICA, 16, Color.BLACK);
            Font fuenteDescripcion = FontFactory.getFont(FontFactory.HELVETICA, 10, Color.GRAY);
            Font fuenteNormal = FontFactory.getFont(FontFactory.HELVETICA, 11, Color.DARK_GRAY);
            Font fuentePuntuacion = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20, Color.BLACK);
            //Nombre de la herramienta
            Paragraph nombre = new Paragraph("CyberRadar", fuenteTitulo);
            nombre.setAlignment(Element.ALIGN_CENTER);
            document.add(nombre);
            //Subtitulo
            Paragraph subtitulo = new Paragraph("Informe de Análisis de Seguridad Web", fuenteSubtitulo);
            subtitulo.setAlignment(Element.ALIGN_CENTER);
            subtitulo.setSpacingAfter(10);
            document.add(subtitulo);
            //Descripción
            Paragraph descripcion = new Paragraph(
                    "Informe generado automáticamente por CyberRadar.",
                    fuenteDescripcion
            );
            descripcion.setAlignment(Element.ALIGN_CENTER);
            descripcion.setSpacingAfter(25);
            document.add(descripcion);
            //Definir formato de la fecha
            DateTimeFormatter formatoFecha = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm");
            //Añadir URL y fecha y hora
            document.add(new Paragraph("URL analizada: " + url, fuenteNormal));
            document.add(new Paragraph(
                    "Fecha del análisis: " + LocalDateTime.now().format(formatoFecha),
                    fuenteNormal
            ));
            document.add(new Paragraph(" "));
            //Puntuación
            Paragraph puntuacionTexto = new Paragraph(
                    "Puntuación global: " + puntuacion + " / 100",
                    fuentePuntuacion
            );
            puntuacionTexto.setAlignment(Element.ALIGN_CENTER);
            puntuacionTexto.setSpacingBefore(15);
            puntuacionTexto.setSpacingAfter(25);
            document.add(puntuacionTexto);
            //Bloque A
            agregarBloque(document, "A. Seguridad de conexión", new String[][]{
                    {"Uso de HTTPS", https},
                    {"Certificado válido", certificado},
                    {"Certificado autofirmado", autofirmado},
                    {"Autoridad certificadora", ca},
                    {"Versión TLS", tls}
            });
            //Bloque B
            agregarBloque(document, "B. Seguridad del servidor", new String[][]{
                    {"Content Security Policy", csp},
                    {"X-Frame-Options", xFrame},
                    {"X-Content-Type-Options", xContent},
                    {"Referrer-Policy", referrer},
                    {"Permissions-Policy", permissions}
            });
            //Bloque C
            agregarBloque(document, "C. Dominio, DNS y propietario", new String[][]{
                    {"DNSSEC", dnssec},
                    {"DNS públicos", dns},
                    {"Antigüedad del dominio", antiguo},
                    {"Listas negras", ln}
            });
            //Bloque D
            agregarBloque(document, "D. Cumplimiento legal y privacidad", new String[][]{
                    {"Política de privacidad", pp},
                    {"Aviso de cookies", cookies},
                    {"Aviso legal", aviso},
                    {"Información de contacto", contacto},
                    {"Atributos de cookies", atCookies}
            });
            //Cerrar documento
            document.close();
            //Devolver el PDF como byte[]
            return out.toByteArray();
        }catch(Exception e){
            return null;
        }
    }

    //Añade un bloque del informe con tabla de comprobación, resultado y recomendación
    private void agregarBloque(Document document, String tituloBloque, String[][] datos) throws DocumentException{
        //Definir fuentes para titulo, cabecera y texto
        Font fuenteTituloBloque = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, Color.BLACK);
        Font fuenteCabecera = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, Color.WHITE);
        Font fuenteTexto = FontFactory.getFont(FontFactory.HELVETICA, 9, Color.BLACK);
        //Titulo del bloque
        Paragraph titulo = new Paragraph(tituloBloque, fuenteTituloBloque);
        titulo.setSpacingBefore(25);
        titulo.setSpacingAfter(8);
        //Crear tabla con 3 columnas
        PdfPTable tabla = new PdfPTable(3);
        tabla.setWidthPercentage(100);
        tabla.setWidths(new float[]{28, 22, 50});
        tabla.setKeepTogether(true);
        tabla.setSplitLate(false);
        //Añadir cabeceras
        agregarCeldaCabecera(tabla, "Comprobación", fuenteCabecera);
        agregarCeldaCabecera(tabla, "Resultado", fuenteCabecera);
        agregarCeldaCabecera(tabla, "Recomendación", fuenteCabecera);
        //Recorrer cada fila de datos recibida
        for(String[] fila : datos){
            //Primera columna: Nombre de la comprobación
            PdfPCell celdaNombre = new PdfPCell(new Phrase(fila[0], fuenteTexto));
            celdaNombre.setPadding(7);
            celdaNombre.setVerticalAlignment(Element.ALIGN_MIDDLE);
            //Obtener color en función del resultado obtenido
            Font fuenteResultado = obtenerFuenteResultado(fila[0], fila[1]);
            //Segunda columna: Resultado obtenido
            PdfPCell celdaValor = new PdfPCell(new Phrase(fila[1], fuenteResultado));
            celdaValor.setPadding(7);
            celdaValor.setVerticalAlignment(Element.ALIGN_MIDDLE);
            //Generar recomendación
            String recomendacion = obtenerRecomendacion(fila[0], fila[1]);
            //Tercera columna: Recomendación
            PdfPCell celdaRecomendacion = new PdfPCell(new Phrase(recomendacion, fuenteTexto));
            celdaRecomendacion.setPadding(7);
            celdaRecomendacion.setVerticalAlignment(Element.ALIGN_MIDDLE);
            //Añadir las 3 celdas a la tabla
            tabla.addCell(celdaNombre);
            tabla.addCell(celdaValor);
            tabla.addCell(celdaRecomendacion);
        }

        //Contenedor para mantener juntos el título y la tabla
        PdfPTable contenedor = new PdfPTable(1);
        contenedor.setWidthPercentage(100);
        contenedor.setKeepTogether(true);

        PdfPCell celdaContenedor = new PdfPCell();
        celdaContenedor.setBorder(Rectangle.NO_BORDER);
        celdaContenedor.setPadding(0);

        celdaContenedor.addElement(titulo);
        celdaContenedor.addElement(tabla);

        contenedor.addCell(celdaContenedor);

        //Añadir al documento
        document.add(contenedor);
    }

    //Añadir una celda de cabecera a la tabla
    private void agregarCeldaCabecera(PdfPTable tabla, String texto, Font fuenteCabecera){
        PdfPCell celda = new PdfPCell(new Phrase(texto, fuenteCabecera));
        celda.setBackgroundColor(new Color(34, 197, 94));
        celda.setPadding(8);
        celda.setHorizontalAlignment(Element.ALIGN_CENTER);
        celda.setVerticalAlignment(Element.ALIGN_MIDDLE);
        tabla.addCell(celda);
    }

    //Generar recomendación según la comprobación y el resultado obtenido
    private String obtenerRecomendacion(String comprobacion, String resultado){
        if(resultado == null){
            return "No se ha podido obtener el resultado. Se recomienda revisar esta comprobación manualmente.";
        }
        //A minúsculas para evitar errores
        String c = comprobacion.toLowerCase();
        String r = resultado.toLowerCase();

        
        //Bloque A
        if(c.contains("https")){
            if(r.contains("sí")){
                return "La comunicación está cifrada mediante HTTPS, lo que protege la información transmitida entre el usuario y el sitio web.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda habilitar HTTPS para cifrar la comunicación y evitar que los datos puedan ser interceptados.";
            }
        }
        if(c.contains("certificado válido")){
            if(r.contains("sí")){
                return "El certificado es válido y permite verificar correctamente la identidad del sitio web.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda instalar un certificado válido, vigente y emitido por una autoridad certificadora de confianza.";
            }
        }
        if(c.contains("autofirmado")){
            if(r.contains("no")){
                return "El certificado no es autofirmado, por lo que ofrece mayor confianza al usuario.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda sustituir el certificado autofirmado por uno emitido por una autoridad certificadora reconocida para aumentar la confianza.";
            }
        }
        if(c.contains("autoridad certificadora")){
            if(r.contains("confiable")){
                return "La autoridad certificadora utilizada es confiable y aporta mayor seguridad al certificado del sitio web.";
            }else if(r.contains("poco")){
                return "La autoridad certificadora utilizada ofrece una confianza limitada. Se recomienda valorar el uso de una entidad certificadora más reconocida.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda revisar la autoridad certificadora utilizada y asegurarse de que sea reconocida y confiable.";
            }
        }
        if(c.contains("tls")){
            if(r.contains("seguro") && !r.contains("inseguro")){
                return "La versión TLS utilizada ofrece un nivel adecuado de seguridad para la comunicación.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda actualizar la configuración del servidor para utilizar TLS 1.2 o TLS 1.3 y deshabilitar los protocolos obsoletos.";
            }
        }
        //Bloque B
        if(c.contains("content security") || c.contains("csp")){
            if(r.contains("sí")){
                return "La política Content-Security-Policy ayuda a reducir ataques de inyección de código y mejora la seguridad del sitio web.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda implementar la cabecera Content-Security-Policy para restringir los recursos que puede cargar la página.";
            }
        }
        if(c.contains("x-frame")){
            if(r.contains("seguro") && !r.contains("inseguro")){
                return "La configuración de X-Frame-Options protege correctamente frente a ataques de clickjacking.";
            }else if(r.contains("error")){
                return "Error";
            }else if(r.contains("detectada")){
                return "Se recomienda implementar la cabecera X-Frame-Options.";
            }else{
                return "Se recomienda configurar X-Frame-Options con valores como DENY o SAMEORIGIN.";
            }
        }
        if(c.contains("x-content")){
            if(r.contains("seguro") && !r.contains("inseguro")){
                return "La cabecera X-Content-Type-Options evita interpretaciones inseguras del tipo de contenido por parte del navegador.";
            }else if(r.contains("error")){
                return "Error";
            }else if(r.contains("detectada")){
                return "Se recomienda implementar la cabecera X-Content-Type-Options.";
            }else{
                return "Se recomienda configurar X-Content-Type-Options con el valor nosniff.";
            }
        }
        if(c.contains("referrer")){
            if(r.contains("seguro") && !r.contains("inseguro")){
                return "La política Referrer-Policy protege adecuadamente la privacidad del usuario durante la navegación.";
            }else if(r.contains("intermedio")){
                return "La política utilizada proporciona una protección parcial. Se recomienda utilizar una configuración más restrictiva cuando sea posible.";
            }else if(r.contains("error")){
                return "Error";
            }else if(r.contains("detectada")){
                return "Se recomienda implementar una Referrer-Policy.";
            }else{
                return "Se recomienda configurar una Referrer-Policy adecuada para limitar la información compartida con sitios externos.";
            }
        }
        if(c.contains("permissions")){
            if(r.contains("seguro") && !r.contains("inseguro")){
                return "La política limita adecuadamente el acceso a funcionalidades sensibles del navegador.";
            }else if(r.contains("intermedio")){
                return "Se recomienda restringir aquellos permisos que no sean necesarios para el funcionamiento del sitio web.";
            }else if(r.contains("error")){
                return "Error";
            }else if(r.contains("detectada")){
                return "Se recomienda verificar la configuración de Permissions-Policy.";
            }else{
                return "Se recomienda implementar una política de permisos que limite el acceso a recursos como cámara, micrófono o geolocalización.";
            }
        }
        //Bloque C
        if(c.contains("dnssec")){
            if(r.contains("sí")){
                return "DNSSEC protege la resolución DNS frente a manipulaciones y ataques de suplantación.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda habilitar DNSSEC para reforzar la seguridad del dominio.";
            }
        }
        if(c.contains("dns públicos")){
            if(r.contains("seguro") && !r.contains("inseguro")){
                return "El dominio se resuelve correctamente desde los diferentes servidores DNS públicos analizados, lo que indica una configuración adecuada.";
            }else if(r.contains("intermedio")){
                return "Se recomienda revisar la configuración de los registros DNS y verificar su correcta propagación entre los distintos servidores públicos.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda comprobar la configuración del dominio y de sus servidores DNS autorizados, verificando que los registros estén correctamente publicados y accesibles.";
            }
        }
        if(c.contains("antigüedad")){
            if(r.contains("seguro") && !r.contains("inseguro")){
                return "La antigüedad del dominio aporta un indicador adicional de confianza.";
            }else if(r.contains("intermedio")){
                return "Se recomienda complementar esta información con otras comprobaciones de seguridad y reputación.";
            }else if(r.contains("error")){
                return "Error";
            }else if(r.contains("determinar")){
                return "No se ha podido determinar la antigüedad del dominio. Se recomienda verificar esta información manualmente.";
            }else{
                return "Al tratarse de un dominio de reciente creación, conviene extremar las precauciones antes de confiar plenamente en él.";
            }
        }
        if(c.contains("listas negras")){
            if(r.contains("seguro") && !r.contains("inseguro")){
                return "El dominio no figura en listas negras conocidas, lo que constituye un indicador positivo.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda revisar la reputación del dominio y solicitar su retirada de las listas negras si la inclusión no está justificada.";
            }
        }
        //Bloque D
        if(c.contains("privacidad")){
            if(r.contains("sí")){
                return "El sitio dispone de una política de privacidad que informa sobre el tratamiento de los datos personales.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda incorporar una política de privacidad clara y accesible.";
            }
        }
        if(c.contains("cookies") && !c.contains("atributos")){
            if(r.contains("sí")){
                return "El sitio informa al usuario sobre el uso de cookies.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda incluir un aviso de cookies conforme a la normativa aplicable.";
            }
        }
        if(c.contains("aviso legal")){
            if(r.contains("sí")){
                return "El sitio facilita información legal sobre el responsable de la página web.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda incorporar un aviso legal o unos términos y condiciones accesibles para el usuario.";
            }
        }
        if(c.contains("contacto")){
            if(r.contains("sí")){
                return "El usuario dispone de información de contacto del responsable del sitio web.";
            }else if(r.contains("error")){
                return "Error";
            }else{
                return "Se recomienda proporcionar un medio de contacto visible y actualizado.";
            }
        }
        if(c.contains("atributos de cookies")){
            if(r.contains("seguro") && !r.contains("inseguro")){
                return "Las cookies incorporan los principales atributos de seguridad recomendados.";
            }else if(r.contains("intermedio")){
                return "Se recomienda completar la configuración incluyendo los tres atributos de seguridad Secure, HttpOnly y SameSite.";
            }else if(r.contains("error")){
                return "Error";
            }else if(r.contains("detectaron")){
                return "No se han detectado cookies durante el análisis realizado. Esto puede deberse a que el sitio no las utilice.";
            }else{
                return "Se recomienda configurar las cookies utilizando los atributos Secure, HttpOnly y SameSite para mejorar la protección frente a ataques habituales.";
            }
        }
        return "Se recomienda revisar esta comprobación para valorar posibles mejoras de seguridad.";
    }

    //Devuelve la fuente del resultado con color según su estado
    private Font obtenerFuenteResultado(String comprobacion, String resultado){
        Color color = obtenerColorResultado(comprobacion, resultado);
        return FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, color);
    }

    //Determina el color del resultado
    private Color obtenerColorResultado(String comprobacion, String resultado){
        if(resultado == null){
            return new Color(220, 38, 38);
        }

        String r = resultado.toLowerCase();
        String c = comprobacion.toLowerCase();

        if(c.contains("autofirmado")){
            if(r.contains("no")){
                return new Color(46, 125, 50);
            }else{
                return new Color(220, 38, 38);
            }
        }
        if(r.contains("intermedio")|| r.contains("poco")){
            return new Color(245, 124, 0);
        }
        if(r.contains("sí") || (r.contains("seguro") && !r.contains("inseguro")) || r.contains("confiable")){
            return new Color(46, 125, 50);
        }
        if(r.contains("no")|| r.contains("inseguro")|| r.contains("desconocida")){
            return new Color(220, 38, 38);
        }
        return Color.BLACK;
    }
}