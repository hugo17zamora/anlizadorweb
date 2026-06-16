package com.tfg.analizadorweb.model;

//Clase que representa el resultado completo del análisis
public class ResultadoAnalisis{
    private String url;
    private int puntuacion;
    //Bloque A
    private String https;
    private String certificado;
    private String autofirmado;
    private String ca;
    private String tls;
    //Bloque B
    private String csp;
    private String xFrame;
    private String xContent;
    private String referrer;
    private String permissions;
    //Bloque C
    private String dnssec;
    private String dns;
    private String antiguo;
    private String ln;
    //Bloque D
    private String pp;
    private String cookies;
    private String aviso;
    private String contacto;
    private String atCookies;
    
    //Constructor
    public ResultadoAnalisis(
                            String url, int puntuacion,
                            //Bloque A
                            String https, String certificado, String autofirmado, String ca, String tls,
                            //Bloque B
                            String csp, String xFrame, String xContent, String referrer, String permissions,
                            //Bloque C
                            String dnssec, String dns, String antiguo, String ln,
                            //Bloque D
                            String pp, String cookies, String aviso, String contacto, String atCookies){
        this.url = url;
        this.puntuacion = puntuacion;
        //Bloque A
        this.https = https;
        this.certificado = certificado;
        this.autofirmado = autofirmado;
        this.ca = ca;
        this.tls = tls;
        //Bloque B
        this.csp = csp;
        this.xFrame = xFrame;
        this.xContent = xContent;
        this.referrer = referrer;
        this.permissions = permissions;
        //Bloque C
        this.dnssec = dnssec;
        this.dns = dns;
        this.antiguo = antiguo;
        this.ln = ln;
        //Bloque D
        this.pp = pp;
        this.cookies = cookies;
        this.aviso = aviso;
        this.contacto = contacto;
        this.atCookies = atCookies;
    }
    //Getters
    public String getUrl(){ 
        return url; 
    }
    public int getPuntuacion(){ 
        return puntuacion; 
    }
    //Bloque A
    public String getHttps(){ 
        return https;
    }
    public String getCertificado(){ 
        return certificado; 
    }
    public String getAutofirmado(){ 
        return autofirmado; 
    }
    public String getCa(){ 
        return ca; 
    }
    public String getTls(){ 
        return tls; 
    }
    //Bloque B
    public String getCsp(){ 
        return csp; 
    }
    public String getXFrame(){ 
        return xFrame; 
    }
    public String getXContent(){ 
        return xContent; 
    }
    public String getReferrer(){ 
        return referrer; 
    }
    public String getPermissions(){ 
        return permissions; 
    }
    //Bloque C
    public String getDnssec(){
        return dnssec;
    }
    public String getDns(){
        return dns;
    }
    public String getAntiguo(){
        return antiguo;
    }
    public String getLn(){
        return ln;
    }
    //Bloque D
    public String getPp(){
        return pp;
    }
    public String getCookies(){
        return cookies;
    }
    public String getAviso(){
        return aviso;
    }
    public String getContacto(){
        return contacto;
    }
    public String getAtCookies(){
        return atCookies;
    }
}