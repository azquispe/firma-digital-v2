package com.ganaseguro.firmador.dto;

import java.util.List;

public class RequestFirmarLoteArchivosDTO {
    private String userName;
    private String pin;
    private List<String> pdfBase64;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public List<String> getPdfBase64() {
        return pdfBase64;
    }

    public void setPdfBase64(List<String> pdfBase64) {
        this.pdfBase64 = pdfBase64;
    }
}
