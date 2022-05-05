package com.ganaseguro.firmador.dto;

public class RequestFirmarDTO {
    private String pin;
    private String pdfBase64;



    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public String getPdfBase64() {
        return pdfBase64;
    }

    public void setPdfBase64(String pdfBase64) {
        this.pdfBase64 = pdfBase64;
    }
}
