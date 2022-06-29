package com.ganaseguro.firmador.services;

import com.ganaseguro.firmador.dto.*;
import jacobitus.token.ExternalSignatureLocal;
import jacobitus.token.Slot;
import jacobitus.token.Token;
import jacobitus.token.TokenPKCS12;
import com.ganaseguro.firmador.utils.FuncionesGenericos;
import com.ganaseguro.firmador.utils.constantes.ConstDiccionarioMensajeFirma;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
import jacobitus.validar.CertDate;
import jacobitus.validar.ContentsChecker;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

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
                    //usuarioFirmante.setPin(iEncryptDecryptService.decryptMessage(usuarioFirmante.getPin()).getElementoGenerico().toString()); // esto se va habilitar cuando desde front ya envie cifrado
                    String vPin =iEncryptDecryptService.decryptMessage(usuarioFirmante.getPin()).getElementoGenerico().toString(); // esto se va habilitar cuando desde front ya envie cifrado
                    token.iniciar(vPin);
                } catch (Exception ex) {
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2004_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2004);
                    return response;
                }

                //VALIDAMOS QUE EL DOCUMENTO SE CONSTRUYA CORRECTAMENTE
                try {
                    this.saveBase64(objLoteUsuarios.getPdfBase64());
                } catch (Exception ex) {
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2005_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2005);
                    return response;
                }

                List<String> labels = token.listarIdentificadorClaves();
                this.firmar(new File(dirdocFirmado + "/documento.pdf"), token.obtenerClavePrivada(labels.get(0)), token.getCertificateChain(labels.get(0)), token.getProviderName());
                objLoteUsuarios.setPdfBase64(FuncionesGenericos.pdfToBase64(dirdocFirmado + "/documento.firmado.pdf")); // actualizamos el pdf para el siguiente firma
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
            // VALIDAMOS SI EXISTE CARPETA DEL USUARIO
            if (!file.exists()) {
                response.setMensaje(ConstDiccionarioMensajeFirma.COD2003_MENSAJE);
                response.setCodigo(ConstDiccionarioMensajeFirma.COD2003);
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
            Token token = new TokenPKCS12(new Slot(pathSofToken));
            for (String archivo : objFirmaLoteArchivos.getPdfBase64()) {



                //VALIDAMOS QUE EL PIN SEA CORRECTO
                try {
                    String vPin= iEncryptDecryptService.decryptMessage(objFirmaLoteArchivos.getPin()).getElementoGenerico().toString(); // Decifra el PIN
                    token.iniciar(vPin);
                } catch (Exception ex) {
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2004_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2004);
                    return response;
                }

                //VALIDAMOS QUE EL DOCUMENTO SE CONSTRUYA CORRECTAMENTE
                try {
                    this.saveBase64(archivo);
                } catch (Exception ex) {
                    response.setMensaje(ConstDiccionarioMensajeFirma.COD2005_MENSAJE);
                    response.setCodigo(ConstDiccionarioMensajeFirma.COD2005);
                    return response;
                }

                List<String> labels = token.listarIdentificadorClaves();
                this.firmar(new File(dirdocFirmado + "/documento.pdf"), token.obtenerClavePrivada(labels.get(0)), token.getCertificateChain(labels.get(0)), token.getProviderName());
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

            //Es recomendable almacenar en un log estos errores...
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
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");

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

    public void firmar(File file, PrivateKey pk, Certificate[] chain, String provider) {
        try {
            PdfReader reader = new PdfReader(file);
            StampingProperties stamp = new StampingProperties();
            stamp.useAppendMode();
            PdfSigner signer = new PdfSigner(reader, new FileOutputStream(file.getPath().replace(".pdf", ".firmado.pdf")), stamp);
            Rectangle rect = new Rectangle(0, 0, 0, 0);
            PdfSignatureAppearance appearance = signer.getSignatureAppearance();
            appearance.setPageRect(rect);
            IExternalDigest digest = new BouncyCastleDigest();
            IExternalSignature signature = new ExternalSignatureLocal(pk, provider);
            signer.signDetached(digest, signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);
        } catch (IOException ex) {
            System.out.println("No se encontro el archivo " + file);
        } catch (GeneralSecurityException ex) {
            System.err.println("Error inesperado al firmar el documetno.");
        }
    }

    public void saveBase64(String pBase64) throws Exception {
        File file = new File(dirdocFirmado + "/documento.pdf");
        FileOutputStream fos = new FileOutputStream(file);
        byte[] decoder = Base64.getDecoder().decode(pBase64);
        fos.write(decoder);
    }
}
