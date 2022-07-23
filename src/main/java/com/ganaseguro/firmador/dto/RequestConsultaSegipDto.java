package com.ganaseguro.firmador.dto;

public class RequestConsultaSegipDto {
    private String ci;
    private String documentCity;
    private String birthdate;

    public String getCi() {
        return ci;
    }

    public void setCi(String ci) {
        this.ci = ci;
    }

    public String getDocumentCity() {
        return documentCity;
    }

    public void setDocumentCity(String documentCity) {
        this.documentCity = documentCity;
    }

    public String getBirthdate() {
        return birthdate;
    }

    public void setBirthdate(String birthdate) {
        this.birthdate = birthdate;
    }
}
