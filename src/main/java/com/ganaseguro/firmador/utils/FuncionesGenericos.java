package com.ganaseguro.firmador.utils;

import com.ganaseguro.firmador.security.RSA_for_PIN;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import jacobitus.token.ExternalSignatureLocal;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class FuncionesGenericos {
    public static String pdfToBase64(String pPathFile) {
        try {
            byte[] input_file = Files.readAllBytes(Paths.get(pPathFile));
            byte[] encodedBytes = Base64.getEncoder().encode(input_file);
            return  new String(encodedBytes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    /*public static  PublicKey readPublicKey() throws Exception {
        String publicKeyPEM = RSA_for_PIN.RSA_PUBLIC
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] keyBytes = Base64.getMimeDecoder().decode(publicKeyPEM.getBytes());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }*/
    public static PrivateKey readPrivateKey() throws Exception {
        String privateKeyPEM = RSA_for_PIN.RSA_PRIVATE
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");

        byte[] keyBytes = Base64.getMimeDecoder().decode(privateKeyPEM.getBytes());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        return key;

    }

    public static Boolean firmar(File file, PrivateKey pk, Certificate[] chain, String provider) {
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
            return true;
        } catch (IOException ex) {
            System.out.println("No se encontro el archivo " + file);
            return false;
        } catch (GeneralSecurityException ex) {
            System.err.println("Error inesperado al firmar el documetno.");
            return false;
        }
    }
    public static void saveBase64ToFile(String pBase64, String pPath) throws Exception {
        File file = new File(pPath);
        FileOutputStream fos = new FileOutputStream(file);
        byte[] decoder = Base64.getDecoder().decode(pBase64);
        fos.write(decoder);
    }

}
