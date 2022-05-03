package com.ganaseguro.firmador.services;

import com.ganaseguro.firmador.dto.CertDate;
import com.ganaseguro.firmador.dto.ContentsChecker;
import com.ganaseguro.firmador.dto.RequestFirmarDTO;
import com.ganaseguro.firmador.dto.ResponseDTO;
import com.ganaseguro.firmador.token.ExternalSignatureLocal;
import com.ganaseguro.firmador.token.Slot;
import com.ganaseguro.firmador.token.Token;
import com.ganaseguro.firmador.token.TokenPKCS12;
import com.ganaseguro.firmador.utils.FuncionesGenericos;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
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

import static com.ganaseguro.firmador.dto.Validar.verificarOcsp;
import static com.ganaseguro.firmador.dto.Validar.verificarPKI;

@Service
public class FirmaService implements IFirmaService {

    @Value("${dir.softoken}")
    private String dirSoftoken ;

    @Value("${dir.docFirmado}")
    private String dirdocFirmado ;

    @Override
    public ResponseDTO firmarDocumento(RequestFirmarDTO objDatosFirmar , String pUserName) {
        String pathSofToken= dirSoftoken +"/"+pUserName+ "/softoken.p12";
        Token token = new TokenPKCS12(new Slot(pathSofToken));
        ResponseDTO response = new ResponseDTO();
        try {
            this.saveBase64(objDatosFirmar.getPdfBase64());
            token.iniciar(objDatosFirmar.getPin());
            List<String> labels = token.listarIdentificadorClaves();
            this.firmar(new File(dirdocFirmado+"/documento.pdf"), token.obtenerClavePrivada(labels.get(0)), token.getCertificateChain(labels.get(0)), token.getProviderName());
            token.salir();
            response.setMensaje("Se ha relizado la firma correctamente");
            response.setFinalizado(true);
            response.setElementoGenerico(FuncionesGenericos.pdfToBase64(dirdocFirmado+"/documento.firmado.pdf"));
            return response;

        } catch (GeneralSecurityException ex) {

            response.setMensaje(ex.toString());
            response.setFinalizado(false);
            return response;
        }
    }

    @Override
    public ResponseDTO verificarFirmasPdf(String pdfBase64) {
        ResponseDTO result = new ResponseDTO();
        try{
            byte[] decodeFile = Base64.getDecoder().decode(pdfBase64);
            if(decodeFile==null){
                result.setFinalizado(false);
                result.setMensaje("Datos requeridos pdf.");
                return result;
            }
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            List<CertDate> certificados = this.listarCertificados(new ByteArrayInputStream(decodeFile));
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");


            List<Map<String, Object>> firmas = new ArrayList<>();



            for (CertDate cert: certificados) {
                Map<String, Object> firma = new HashMap<>();
                firma.put("noModificado", cert.isValid());
                firma.put("cadenaConfianza", cert.isPKI());
                firma.put("firmadoDuranteVigencia", cert.isActive());
                firma.put("firmadoAntesRevocacion", cert.isOCSP());
                firma.put("versionado", cert.isValidAlerted());
                firma.put("timeStamp", cert.getTimeStamp() != null);
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
            result.setFinalizado(true);
            result.setMensaje("Se validó las firmas correctamente!");
            result.setElementoGenerico(firmas);
            return result;

        }catch (Exception ex){
            result.setFinalizado(false);
            result.setMensaje(ex.getMessage());
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
                referenceObject = ((PdfIndirectReference)referenceObject).getRefersTo(true);
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
    public  void firmar(File file, PrivateKey pk, Certificate[] chain, String provider) {
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
    public void saveBase64(String pBase64){
        File file = new File(dirdocFirmado+"/documento.pdf");
        try ( FileOutputStream fos = new FileOutputStream(file); ) {
            byte[] decoder = Base64.getDecoder().decode(pBase64);
            fos.write(decoder);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
