package com.ganaseguro.firmador.dto;

public class ResponseDTO<T> {
    private String codigo;
    private String mensaje;
    private T elementoGenerico;

    public String getCodigo() {
        return codigo;
    }

    public void setCodigo(String codigo) {
        this.codigo = codigo;
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
