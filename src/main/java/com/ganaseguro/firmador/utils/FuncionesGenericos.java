package com.ganaseguro.firmador.utils;

import com.ganaseguro.firmador.dto.ResponseDto;
import com.ganaseguro.firmador.security.RSA_for_PIN;
import com.ganaseguro.firmador.utils.constantes.ConstDiccionarioMensajeFirma;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import jacobitus.token.ExternalSignatureLocal;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.*;

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


    public static ResponseDto saveBase64ToFile_Old(String pBase64, String pPath)  {
        ResponseDto res = new ResponseDto();
        File file = new File(pPath);
        FileOutputStream fos = null;
        try{
            fos = new FileOutputStream(file);
            byte[] decoder = Base64.getDecoder().decode(pBase64);
            fos.write(decoder);
            fos.close();
            res.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
            res.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);
            return res;
        }catch (IOException ex){
            res.setCodigo(ConstDiccionarioMensajeFirma.COD1000);
            res.setMensaje(ConstDiccionarioMensajeFirma.COD1000_MENSAJE);
            return res;
        }
    }

    public static boolean   saveBase64ToFile(String pBase64,
                                               String pPath) {

        try{
            byte[] decoder = Base64.getDecoder().decode(pBase64);
            Files.write(Paths.get(pPath), decoder);

            return true;
        }catch (IOException  ex){
            return false;
        }

    }



    public static <T> List<T> eliminarDuplicados(List<T> list)
    {

        // Create a new LinkedHashSet
        Set<T> set = new LinkedHashSet<>();

        // Add the elements to set
        set.addAll(list);

        // Clear the list
        list.clear();

        // add the elements of set
        // with no duplicates to the list
        list.addAll(set);

        // return the list
        return list;
    }

    public static String CovertirDateToString(Date pFecha) {
        try {
            Timestamp vFechaHora = new Timestamp(pFecha.getTime());

            SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy hh:mm:ss");
            return sdf.format(vFechaHora );

        }
        catch(Exception ex) {
            return null;
        }
    }
}
