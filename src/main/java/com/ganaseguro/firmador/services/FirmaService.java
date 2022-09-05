package com.ganaseguro.firmador.services;

import com.ganaseguro.firmador.dto.*;
import com.ganaseguro.firmador.utils.FuncionesFirma;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import jacobitus.token.*;
import com.ganaseguro.firmador.utils.FuncionesGenericos;
import com.ganaseguro.firmador.utils.constantes.ConstDiccionarioMensajeFirma;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
import jacobitus.validar.CertDate;
import jacobitus.validar.ContentsChecker;
import jacobitus.validar.DatosCertificado;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.codehaus.jettison.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;


import org.codehaus.jettison.json.JSONArray;


import static jacobitus.validar.Validar.verificarOcsp;
import static jacobitus.validar.Validar.verificarPKI;

@Service
public class FirmaService implements IFirmaService {

    @Value("${dir.softoken}")
    private String dirSoftoken;

    @Value("${dir.docFirmado}")
    private String dirdocFirmado;

    @Value("${azure.storage.conection}")
    private String connectStr;

    @Value("${azure.storage.namecontent}")
    private String nameContent;


    @Autowired
    IEncryptDecryptService iEncryptDecryptService;

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");


    @Override
    public ResponseDto firmar(RequestFirmarDto requestFirmarDto) {
        ResponseDto result = new ResponseDto();
        List<String> logObservaciones = new ArrayList<>();
        try {
            // VALIDAMOS QUE EXISTA DOCUMENTOS PDF
            if (requestFirmarDto.getListaPdf().isEmpty()) {
                logObservaciones.add(ConstDiccionarioMensajeFirma.COD2002 + " - " + ConstDiccionarioMensajeFirma.COD2002_MENSAJE);
            }
            // VALIDAMOS QUE EXISTA USUARIOS FIRMANTES
            if (requestFirmarDto.getListaUsuario().isEmpty()) {
                logObservaciones.add(ConstDiccionarioMensajeFirma.COD2001 + " - " + ConstDiccionarioMensajeFirma.COD2001_MENSAJE);
            }
            for (UsuariosFirmantesDto objUsuarios : requestFirmarDto.getListaUsuario()) {

                // VALIDAMOS SI EL REQUEST TRAE NOMBRE DE USUARIO
                if (objUsuarios.getUserName() == null || objUsuarios.getUserName().trim() == "") {
                    logObservaciones.add(ConstDiccionarioMensajeFirma.COD2001 + " - " + ConstDiccionarioMensajeFirma.COD2001_MENSAJE);
                    continue;
                }

                // DESCARGAMOS SOFTOKEN AL SITIO
                //https://docs.microsoft.com/es-es/azure/storage/blobs/storage-quickstart-blobs-java?tabs=powershell%2Cenvironment-variable-windows
                boolean descargaCorrecta = FuncionesFirma.downloadSoftoken(connectStr, nameContent, dirSoftoken, objUsuarios.getUserName() + ".p12");
                if (!descargaCorrecta) {
                    logObservaciones.add(ConstDiccionarioMensajeFirma.COD2003 + " - " + ConstDiccionarioMensajeFirma.COD2003_MENSAJE );
                    continue;
                }

                // VALIDAMOS QUE EXISTA CERTIFICADOS
                String pathSofToken = dirSoftoken + "/" + objUsuarios.getUserName() + ".p12";
                /*File file = new File(pathSofToken);
                if (!file.exists()) {
                    logObservaciones.add(ConstDiccionarioMensajeFirma.COD2003 + " - " + ConstDiccionarioMensajeFirma.COD2003_MENSAJE + ", Usuario: " + objUsuarios.getUserName());
                    continue;
                }*/

                Token token = new TokenPKCS12(new Slot(pathSofToken));

                //VALIDAMOS QUE EL PIN SEA CORRECTO
                try {
                    String vPin = iEncryptDecryptService.decryptMessage(objUsuarios.getPin()).getElementoGenerico().toString();
                    token.iniciar(vPin);
                } catch (Exception ex) {
                    logObservaciones.add(ConstDiccionarioMensajeFirma.COD2004 + " - " + ConstDiccionarioMensajeFirma.COD2004_MENSAJE + ", Usuario: " + objUsuarios.getUserName());
                    continue;
                }


                List<String> lstArchivosFirmados = new ArrayList<>();
                for (String pdf : requestFirmarDto.getListaPdf()) {

                    //VALIDAMOS SI EL REQUEST TRAE BASE 64 (DOCUMENTOS)
                    if (pdf == null || pdf.trim() == "") {
                        logObservaciones.add(ConstDiccionarioMensajeFirma.COD2002 + " - " + ConstDiccionarioMensajeFirma.COD2002_MENSAJE);
                        continue;
                    }

                    //GUARDAMOS PDF 64 (AUN SIN FIRMAR) EN UNA UBICACION FISICA
                    Boolean guardadoCorrecto = FuncionesGenericos.saveBase64ToFile(pdf, dirdocFirmado + "/documento.pdf");
                    if (!guardadoCorrecto ) {
                        logObservaciones.add(ConstDiccionarioMensajeFirma.COD2005 + " - " + ConstDiccionarioMensajeFirma.COD2005_MENSAJE);
                    }


                    //SE FIRMA LOS PDFS
                    Boolean firmadoCorrecto = FuncionesFirma.firmar(new File( dirdocFirmado + "/documento.pdf"), token);
                    if (!firmadoCorrecto) {
                        logObservaciones.add(ConstDiccionarioMensajeFirma.COD2007 + " - " + ConstDiccionarioMensajeFirma.COD2007_MENSAJE);
                    }

                    String base64Firmado = FuncionesGenericos.pdfToBase64(dirdocFirmado + "/documento.firmado.pdf");
                    lstArchivosFirmados.add(base64Firmado);


                }
                requestFirmarDto.setListaPdf(lstArchivosFirmados);
                token.salir();

                //Files.delete(Paths.get(pathSofToken));

            }
            int numero_documento = 1;
            for (String base64Firmado : requestFirmarDto.getListaPdf()) {
                ResponseDto resp = this.verificarFirmasPdf(base64Firmado);
                if (!resp.getCodigo().equals(ConstDiccionarioMensajeFirma.COD1000)) {
                    logObservaciones.add(resp.getCodigo() + " - " + resp.getMensaje());
                }
                List<Map<String, Object>> lstFirmas = (List<Map<String, Object>>) resp.getElementoGenerico();
                logObservaciones.addAll(FuncionesFirma.verificarObservacionEnFirmas(lstFirmas, numero_documento));
                numero_documento++;
            }


        } catch (Exception ex) {
            logObservaciones.add(ConstDiccionarioMensajeFirma.COD2000 + " - " + ConstDiccionarioMensajeFirma.COD2000_MENSAJE);

        }
        if (!logObservaciones.isEmpty()) {
            result.setMensaje(ConstDiccionarioMensajeFirma.COD2008_MENSAJE);
            result.setCodigo(ConstDiccionarioMensajeFirma.COD2008);
            result.setElementoGenerico(FuncionesGenericos.eliminarDuplicados(logObservaciones));
            return result;
        } else {
            result.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);
            result.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
            result.setElementoGenerico(requestFirmarDto.getListaPdf());
            return result;
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
                //firma.put("timeStamp", cert.getTimeStamp() != null);  // ALVARO DE ADSIB INDICA QUE ESTE CAMPO AUN NO ESTA EN PRODUCIÓN
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


}
