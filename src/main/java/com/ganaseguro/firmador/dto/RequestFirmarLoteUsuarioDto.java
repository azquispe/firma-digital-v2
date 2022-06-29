package com.ganaseguro.firmador.dto;

import java.util.List;

public class RequestFirmarLoteUsuarioDto {

    private String pdfBase64;
    private List<UsuariosFirmantesDto> lstUsuarioFirmantes;


    public String getPdfBase64() {
        return pdfBase64;
    }

    public void setPdfBase64(String pdfBase64) {
        this.pdfBase64 = pdfBase64;
    }

    public List<UsuariosFirmantesDto> getLstUsuarioFirmantes() {
        return lstUsuarioFirmantes;
    }

    public void setLstUsuarioFirmantes(List<UsuariosFirmantesDto> lstUsuarioFirmantes) {
        this.lstUsuarioFirmantes = lstUsuarioFirmantes;
    }
}
