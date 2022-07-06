package com.ganaseguro.firmador.services;

import com.ganaseguro.firmador.dto.*;
import com.ganaseguro.firmador.utils.FuncionesFechas;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import jacobitus.token.*;
import com.ganaseguro.firmador.utils.FuncionesGenericos;
import com.ganaseguro.firmador.utils.constantes.ConstDiccionarioMensajeFirma;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
import jacobitus.validar.CertDate;
import jacobitus.validar.ContentsChecker;
import jacobitus.validar.DatosCertificado;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;


import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


import static jacobitus.validar.Validar.verificarOcsp;
import static jacobitus.validar.Validar.verificarPKI;

@Service
public class FirmaService implements IFirmaService {

    @Value("${dir.softoken}")
    private String dirSoftoken;

    @Value("${dir.docFirmado}")
    private String dirdocFirmado;

    @Autowired
    IEncryptDecryptService iEncryptDecryptService;

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");

    @Override
    public ResponseDto firmarLoteUsuarios(RequestFirmarLoteUsuarioDto objLoteUsuarios) {
        ResponseDto response = new ResponseDto();
        try {
            // VALIDAMOS SI EL REQUEST TRAE NOMBRE DE USUARIO(S)
            if (objLoteUsuarios.getLstUsuarioFirmantes().size() == 0) {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2001_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2001);
                return response;
            }

            // VALIDAMOS QUE TENGA BASE 64 (PDF A FIRMAR)
            if (objLoteUsuarios.getPdfBase64() == null || objLoteUsuarios.getPdfBase64().trim() == "") {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2002_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2002);
                return response;
            }

            for (UsuariosFirmantesDto usuarioFirmante : objLoteUsuarios.getLstUsuarioFirmantes()) {
                String pathSofToken = dirSoftoken + "/" + usuarioFirmante.getUserName() + "/softoken.p12";
                File file = new File(pathSofToken);

                // VALIDAMOS QUE EXISTA CARPETA DEL USUARIO
                if (!file.exists()) {
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2003_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2003);
                    return response;
                }

                Token token = new TokenPKCS12(new Slot(pathSofToken));

                //VALIDAMOS QUE EL PIN SEA CORRECTO
                try {
                    String vPin = iEncryptDecryptService.decryptMessage(usuarioFirmante.getPin()).getElementoGenerico().toString(); // decifra pin
                    token.iniciar(vPin);
                } catch (Exception ex) {
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2004_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2004);
                    return response;
                }

                // VERIFICAMOS QUE FECHA ESTE VIGENTE
                FechaInicioFinSoftTokenDto objFechas =  this.obtenerFechaValidezDeToken(token);
                if(objFechas==null || objFechas.getFechaFin()==null){
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2008_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2008);
                    return response;
                }
                Date fechaActual = new Date(System.currentTimeMillis());
                if(objFechas.getFechaFin().before(fechaActual)){
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2009_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2009);
                    return response;
                }


                //VALIDAMOS QUE EL DOCUMENTO SE CONSTRUYA CORRECTAMENTE
                try {
                    FuncionesGenericos.saveBase64ToFile(objLoteUsuarios.getPdfBase64(), dirdocFirmado + "/documento.pdf");
                } catch (Exception ex) {
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2005_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2005);
                    return response;
                }

                List<String> labels = token.listarIdentificadorClaves();

                Boolean firmado_Correcto = FuncionesGenericos.firmar(new File(dirdocFirmado + "/documento.pdf"), token.obtenerClavePrivada(labels.get(0)), token.getCertificateChain(labels.get(0)), token.getProviderName());
                // VALIDAMOS QUE EXISTA CARPETA DEL USUARIO
                if (!firmado_Correcto) {
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2007_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2007);
                    return response;
                }

                objLoteUsuarios.setPdfBase64(FuncionesGenericos.pdfToBase64(dirdocFirmado + "/documento.firmado.pdf")); // recojemos el documento firmado y convertimos a Base 64
                token.salir();
            }
            response.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);
            response.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
            response.setElementoGenerico(objLoteUsuarios.getPdfBase64());
            return response;
        } catch (Exception ex) {
            // guardar mensaje en un log .....
            response.setMensaje(ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
            response.setCodigo(ConstDiccionarioMensajeFirma.COD2000);
            return response;
        }

    }

    @Override
    public ResponseDto firmarLoteArchivos(RequestFirmarLoteArchivosDto objFirmaLoteArchivos) {

        ResponseDto response = new ResponseDto();
        try {

            String pathSofToken = dirSoftoken + "/" + objFirmaLoteArchivos.getUserName() + "/softoken.p12";
            File file = new File(pathSofToken);
            // VALIDAMOS SI EXISTE CARPETA DEL USUARIO Y SU SOFTOKEN
            if (!file.exists()) {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2003_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2003);
                return response;
            }
            //VALIDAMOS QUE EL PIN SEA CORRECTO
            Token token = new TokenPKCS12(new Slot(pathSofToken));
            try {
                String vPin = iEncryptDecryptService.decryptMessage(objFirmaLoteArchivos.getPin()).getElementoGenerico().toString(); // decifra pin
                token.iniciar(vPin);
            } catch (Exception ex) {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2004_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2004);
                return response;
            }
            // VERIFICAMOS QUE FECHA ESTE VIGENTE
            FechaInicioFinSoftTokenDto objFechas =  this.obtenerFechaValidezDeToken(token);
            if(objFechas==null || objFechas.getFechaFin()==null){
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2008_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2008);
                return response;
            }
            Date fechaActual = new Date(System.currentTimeMillis());
            if(objFechas.getFechaFin().before(fechaActual)){
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2009_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2009);
                return response;
            }
            // VALIDAMOS SI EL REQUEST TRAE NOMBRE DE USUARIO
            if (objFirmaLoteArchivos.getUserName() == null || objFirmaLoteArchivos.getUserName().trim() == "") {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2001_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2001);
                return response;
            }
            //VALIDAMOS SI EL REQUEST TRAE BASE 64 (DOCUMENTOS)
            if (objFirmaLoteArchivos.getPdfBase64().size() == 0) {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2002_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2002_MENSAJE);
                return response;
            }
            List<String> lstArchivosFirmados = new ArrayList<>();

            for (String archivo : objFirmaLoteArchivos.getPdfBase64()) {
                //Guardamos el PDF Base 64 en una ubicacion fisica
                try {
                    FuncionesGenericos.saveBase64ToFile(archivo, dirdocFirmado + "/documento.pdf");
                } catch (Exception ex) {
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2005_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2005);
                    return response;
                }

                // firmamos
                List<String> llaves = token.listarIdentificadorClaves();
                Boolean firmado_Correcto = FuncionesGenericos.firmar(new File(dirdocFirmado + "/documento.pdf"), token.obtenerClavePrivada(llaves.get(0)), token.getCertificateChain(llaves.get(0)), token.getProviderName());
                if (!firmado_Correcto) {
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2007_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2007);
                    return response;
                }

                // recogemos el doc pdf firmado
                lstArchivosFirmados.add(FuncionesGenericos.pdfToBase64(dirdocFirmado + "/documento.firmado.pdf"));
            }
            token.salir();


            response.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);
            response.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
            response.setElementoGenerico(lstArchivosFirmados);
            return response;

        } catch (GeneralSecurityException ex) {
            // RETORNA MESAJE DESCONOCIDO
            response.setMensaje(ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
            response.setCodigo(ConstDiccionarioMensajeFirma.COD2000);
            return response;

        }
    }

    @Override
    public ResponseDto verificarFirmasPdf(String pdfBase64) {
        ResponseDto result = new ResponseDto();
        try {

            // VALIDAMOS QUE EXISTA DOCUMENTOS PDF
            if (pdfBase64 == null || pdfBase64.trim() == "") {
                result.setCodigo(ConstDiccionarioMensajeFirma.COD2006);
                result.setMensaje(ConstDiccionarioMensajeFirma.COD2006_MENSAJE);
                return result;
            }
            byte[] decodeFile = Base64.getDecoder().decode(pdfBase64);
            // VALIDAMOS QUE EXISTA DOCUMENTOS PDF
            if (decodeFile == null) {
                result.setCodigo(ConstDiccionarioMensajeFirma.COD2006);
                result.setMensaje(ConstDiccionarioMensajeFirma.COD2006_MENSAJE);
                return result;
            }

            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            List<CertDate> certificados = this.listarCertificados(new ByteArrayInputStream(decodeFile));


            List<Map<String, Object>> firmas = new ArrayList<>();

            for (CertDate cert : certificados) {
                Map<String, Object> firma = new HashMap<>();
                firma.put("noModificado", cert.isValid());
                firma.put("cadenaConfianza", cert.isPKI());
                firma.put("firmadoDuranteVigencia", cert.isActive());
                firma.put("firmadoAntesRevocacion", cert.isOCSP());
                firma.put("versionado", cert.isValidAlerted());
                //firma.put("timeStamp", cert.getTimeStamp() != null);  // ALVARO DE ADSIB INDICA QUE ESTE CAMBO AUN NO ESTA EN PRODUCIÓN
                firma.put("fechaFirma", dateFormat.format(cert.getSignDate()));
                Map<String, Object> certificado = new HashMap<>();
                if (cert.getDatos().getComplementoSubject() != null && !cert.getDatos().getComplementoSubject().equals("")) {
                    certificado.put("ci", cert.getDatos().getNumeroDocumentoSubject() + "-" + cert.getDatos().getComplementoSubject());
                } else {
                    certificado.put("ci", cert.getDatos().getNumeroDocumentoSubject());
                }
                certificado.put("nombreSignatario", cert.getDatos().getNombreComunSubject());
                certificado.put("cargoSignatario", cert.getDatos().getCargoSubject());
                certificado.put("organizacionSignatario", cert.getDatos().getOrganizacionSubject());
                certificado.put("emailSignatario", cert.getDatos().getCorreoSubject());
                certificado.put("nombreECA", cert.getDatos().getNombreComunIssuer());
                certificado.put("descripcionECA", cert.getDatos().getDescripcionSubject());
                certificado.put("inicioValidez", dateFormat.format(cert.getDatos().getInicioValidez()));
                certificado.put("finValidez", dateFormat.format(cert.getDatos().getFinValidez()));
                if (cert.getOCSP().getDate() != null) {
                    certificado.put("revocado", dateFormat.format(cert.getOCSP().getDate()));
                }
                firma.put("certificado", certificado);
                firmas.add(firma);
            }
            result.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
            result.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);
            result.setElementoGenerico(firmas);
            return result;

        } catch (Exception ex) {
            result.setCodigo(ConstDiccionarioMensajeFirma.COD2000);
            result.setMensaje(ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
            return result;
        }

    }

    @Override
    public ResponseDto obtieneInformacionCertificado(UsuariosFirmantesDto usuariosFirmantesDto) {
        ResponseDto response = new ResponseDto();
        try {

            String pathSofToken = dirSoftoken + "/" + usuariosFirmantesDto.getUserName() + "/softoken.p12";
            File file = new File(pathSofToken);
            // VALIDAMOS SI EXISTE CARPETA DEL USUARIO
            if (!file.exists()) {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2003_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2003);
                return response;
            }

            // VALIDADMOS PIN CORRECTO
            Token token = new TokenPKCS12(new Slot(pathSofToken));
            try {
                String vPin = iEncryptDecryptService.decryptMessage(usuariosFirmantesDto.getPin()).getElementoGenerico().toString(); // Decifra el PIN
                token.iniciar(vPin);
            } catch (Exception ex) {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2004_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2004);
                return response;
            }
            List<String> llaves = token.listarIdentificadorClaves();
            try {

                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                InputStream is = getClass().getClassLoader().getResourceAsStream("firmadigital_bo.crt");
                List<X509Certificate> intermediates = (List<X509Certificate>) fact.generateCertificates(is);

                JSONObject data_token = new JSONObject();
                data_token.put("certificates", llaves.size());
                data_token.put("data", new JSONArray());
                for (int i = 0; i < llaves.size(); i++) {
                    JSONObject key = new JSONObject();
                    key.put("tipo", "PRIMARY_KEY");
                    key.put("tipo_desc", "Clave Privada");
                    key.put("alias", llaves.get(i));
                    key.put("id", llaves.get(i));
                    X509Certificate cert = token.obtenerCertificado(llaves.get(i));
                    DatosCertificado datos = new DatosCertificado(cert);
                    key.put("tiene_certificado", cert != null);
                    ((JSONArray) data_token.get("data")).put(key);
                    if (key.getBoolean("tiene_certificado")) {
                        JSONObject x509 = new JSONObject();
                        x509.put("tipo", "X509_CERTIFICATE");
                        x509.put("tipo_desc", "Certificado");
                        x509.put("adsib", false);
                        for (X509Certificate intermediate : intermediates) {
                            try {
                                cert.verify(intermediate.getPublicKey());
                                x509.put("adsib", true);
                                break;
                            } catch (GeneralSecurityException ex) {
                            }
                        }
                        x509.put("serialNumber", cert.getSerialNumber().toString(16));
                        x509.put("alias", llaves.get(i));
                        x509.put("id", llaves.get(i));
                        String pem = "-----BEGIN CERTIFICATE-----\n";
                        pem += Base64.getEncoder().encodeToString(cert.getEncoded());
                        pem += "\n-----END CERTIFICATE-----";
                        x509.put("pem", pem);
                        x509.put("validez", new JSONObject());
                        ((JSONObject) x509.get("validez")).put("desde", dateFormat.format(datos.getInicioValidez()));

                        ((JSONObject) x509.get("validez")).put("hasta", dateFormat.format(datos.getFinValidez()));
                        //((JSONObject) x509.get("validez")).put("hasta", dateFormat.format(FuncionesFechas.ConvertirFormatoYYYYMMDD("2022-07-05 23:13")));



                        x509.put("titular", new JSONObject());
                        ((JSONObject) x509.get("titular")).put("dnQualifier", datos.getTipoDocumentoSubject());
                        ((JSONObject) x509.get("titular")).put("uidNumber", datos.getNumeroDocumentoSubject());
                        ((JSONObject) x509.get("titular")).put("UID", datos.getComplementoSubject());
                        ((JSONObject) x509.get("titular")).put("CN", datos.getNombreComunSubject());
                        ((JSONObject) x509.get("titular")).put("T", datos.getCargoSubject());
                        ((JSONObject) x509.get("titular")).put("O", datos.getOrganizacionSubject());
                        ((JSONObject) x509.get("titular")).put("OU", datos.getUnidadOrganizacionalSubject());
                        ((JSONObject) x509.get("titular")).put("EmailAddress", datos.getCorreoSubject());
                        ((JSONObject) x509.get("titular")).put("description", datos.getDescripcionSubject());
                        x509.put("common_name", datos.getNombreComunSubject());
                        x509.put("emisor", new JSONObject());
                        ((JSONObject) x509.get("emisor")).put("CN", datos.getNombreComunIssuer());
                        ((JSONObject) x509.get("emisor")).put("O", datos.getOrganizacionIssuer());
                        ((JSONArray) data_token.get("data")).put(x509);
                    }
                }
                data_token.put("private_keys", llaves.size());

                response.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
                response.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);


                Map<String, Object> map = new Gson()
                        .fromJson(data_token.toString(), new TypeToken<HashMap<String, Object>>() {
                        }.getType());

                response.setElementoGenerico(map);


            } catch (GeneralSecurityException ex) {
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2000);
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
            }

            token.salir();
            return response;

        } catch (Exception ex) {
            response.setCodigo(ConstDiccionarioMensajeFirma.COD2000);
            response.setMensaje(ConstDiccionarioMensajeFirma.COD2000_MENSAJE);
            return response;
        }
    }

    public List<CertDate> listarCertificados(InputStream is) throws Exception {
        Certificate certificateTSA;
        try (InputStreamReader isr = new InputStreamReader(getClass().getClassLoader().getResourceAsStream("timestamp.crt"))) {
            PemReader reader = new PemReader(isr);
            byte[] cert = reader.readPemObject().getContent();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            certificateTSA = certificateFactory.generateCertificate(new ByteArrayInputStream(cert));
            reader.close();
        }

        List<CertDate> certs = new ArrayList<>();
        ContentsChecker pdf = new ContentsChecker(is);
        PdfDocument pdfDocument = new PdfDocument(pdf);
        SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
        List<String> firmas = signatureUtil.getSignatureNames();

        for (String nombre : firmas) {
            PdfDictionary dict = signatureUtil.getSignatureDictionary(nombre);
            PdfArray referenceArray = dict.getAsArray(PdfName.Reference);
            PdfPKCS7 pkcs7 = signatureUtil.readSignatureData(nombre);

            CertDate certDate;
            if (pkcs7.getTimeStampToken() != null && pkcs7.getTimeStampToken().isSignatureValid(new JcaSimpleSignerInfoVerifierBuilder().build(certificateTSA.getPublicKey()))) {
                certDate = new CertDate(nombre, pkcs7.getSigningCertificate(), pkcs7.getSignDate(), pkcs7.getTimeStampDate(), bloqueaDocumento(referenceArray));
            } else {
                certDate = new CertDate(nombre, pkcs7.getSigningCertificate(), pkcs7.getSignDate(), null, bloqueaDocumento(referenceArray));
            }
            certDate.setValid(pkcs7.verifySignatureIntegrityAndAuthenticity());
            certDate.setValidAdd(pdf.checkElementAdded(dict));
            certDate.setPKI(verificarPKI(certDate.getCertificate()));
            certDate.setOCSP(verificarOcsp((X509Certificate) certDate.getCertificate(), certDate.getSignDate()));
            certs.add(certDate);
        }
        return certs;
    }

    private boolean bloqueaDocumento(PdfArray referenceArray) {
        if (referenceArray == null || referenceArray.size() == 0) {
            return false;
        }
        for (PdfObject referenceObject : referenceArray) {
            if (referenceObject.isIndirectReference())
                referenceObject = ((PdfIndirectReference) referenceObject).getRefersTo(true);
            if (referenceObject.isIndirectReference()) {
                continue;
            }
            if (!referenceObject.isDictionary()) {
                continue;
            }
            PdfDictionary reference = (PdfDictionary) referenceObject;

            PdfName method = reference.getAsName(PdfName.TransformMethod);
            if (method == null) {
                continue;
            }
            if (new PdfName("UR").equals(method)) {
                continue;
            }
            if (!PdfName.DocMDP.equals(method) && !PdfName.FieldMDP.equals(method)) {
                continue;
            }

            PdfDictionary transformParams = reference.getAsDictionary(PdfName.TransformParams);
            if (transformParams == null) {
                continue;
            }

            PdfNumber p = transformParams.getAsNumber(PdfName.P);
            if (p != null) {
                return p.intValue() == 1;
            }
        }
        return false;
    }

    @Override
    public FechaInicioFinSoftTokenDto obtenerFechaValidezDeToken (Token token) {

        try{
            FechaInicioFinSoftTokenDto objResp = new FechaInicioFinSoftTokenDto();
            List<String> llaves = token.listarIdentificadorClaves();
            for (int i = 0; i < llaves.size(); i++) {
                X509Certificate cert = token.obtenerCertificado(llaves.get(i));
                DatosCertificado datos = new DatosCertificado(cert);
                objResp.setFechaInicio(datos.getInicioValidez());
                objResp.setFechaFin(datos.getFinValidez());
                //objResp.setFechaFin(FuncionesFechas.ConvertirFormatoYYYYMMDD("2022-07-05 23:13"));

            }
            return objResp;
        }catch (Exception ex){
            return null;
        }

    }

}
