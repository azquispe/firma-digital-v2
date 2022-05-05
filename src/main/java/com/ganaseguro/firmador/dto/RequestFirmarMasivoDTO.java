package com.ganaseguro.firmador.dto;

import java.util.List;

public class RequestFirmarMasivoDTO {

    private String pdfBase64;
    private List<UsuariosFirmantesDTO> lstUsuarioFirmantes;

    public String getPdfBase64() {
        return pdfBase64;
    }

    public void setPdfBase64(String pdfBase64) {
        this.pdfBase64 = pdfBase64;
    }

    public List<UsuariosFirmantesDTO> getLstUsuarioFirmantes() {
        return lstUsuarioFirmantes;
    }

    public void setLstUsuarioFirmantes(List<UsuariosFirmantesDTO> lstUsuarioFirmantes) {
        this.lstUsuarioFirmantes = lstUsuarioFirmantes;
    }
}
