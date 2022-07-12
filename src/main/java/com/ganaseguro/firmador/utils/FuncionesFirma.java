package com.ganaseguro.firmador.utils;

import com.ganaseguro.firmador.dto.ResponseDto;
import com.ganaseguro.firmador.utils.constantes.ConstDiccionarioMensajeFirma;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import jacobitus.token.ExternalSignatureLocal;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

public class FuncionesFirma {
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
    public static List<String> verificarObservacionEnFirmas(List<Map<String, Object>> lstFirmas, int nro_documento){

        List<String> lstMensaje = new ArrayList<>();
        try{
            for (Map<String, Object> objMap:lstFirmas) {
                Map<String, Object> certificado = (Map<String, Object>) objMap.get("certificado");
                if(!(boolean)objMap.get("noModificado")){
                    lstMensaje.add(ConstDiccionarioMensajeFirma.COD2010+" - "+ConstDiccionarioMensajeFirma.COD2010_MENSAJE+", Usuario: "+certificado.get("nombreSignatario")+" al firmar el Documento Nro: "+nro_documento);
                }
                /*if(!(boolean)objMap.get("cadenaConfianza")){
                    lstMensaje.add(ConstDiccionarioMensajeFirma.COD2011+" - "+ConstDiccionarioMensajeFirma.COD2011_MENSAJE+", Usuario: "+certificado.get("nombreSignatario")+" al firmar el Documento Nro: "+nro_documento);
                }*/
                if(!(boolean)objMap.get("firmadoDuranteVigencia")){
                    lstMensaje.add(ConstDiccionarioMensajeFirma.COD2012+" - "+ConstDiccionarioMensajeFirma.COD2012_MENSAJE+", Usuario: "+certificado.get("nombreSignatario")+" al firmar el Documento Nro: "+nro_documento);
                }
                if(!(boolean)objMap.get("firmadoAntesRevocacion")){
                    lstMensaje.add(ConstDiccionarioMensajeFirma.COD2013+" - "+ConstDiccionarioMensajeFirma.COD2013_MENSAJE+", Usuario: "+certificado.get("nombreSignatario")+" al firmar el Documento Nro: "+nro_documento);
                }
            }
            return lstMensaje;
        }catch (Exception ex){
            return new ArrayList<>();
        }
    }
}
