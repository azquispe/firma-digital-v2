package com.ganaseguro.firmador.dto;

public class ResponseDTO<T> {
    private boolean finalizado;
    private String mensaje;
    private T elementoGenerico;

    public boolean isFinalizado() {
        return finalizado;
    }

    public void setFinalizado(boolean finalizado) {
        this.finalizado = finalizado;
    }

    public String getMensaje() {
        return mensaje;
    }

    public void setMensaje(String mensaje) {
        this.mensaje = mensaje;
    }

    public T getElementoGenerico() {
        return elementoGenerico;
    }

    public void setElementoGenerico(T elementoGenerico) {
        this.elementoGenerico = elementoGenerico;
    }
}
