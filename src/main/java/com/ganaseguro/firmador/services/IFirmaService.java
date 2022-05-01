package com.ganaseguro.firmador.services;

import com.ganaseguro.firmador.dto.RequestFirmarDTO;
import com.ganaseguro.firmador.dto.ResponseDTO;

public interface IFirmaService {
    public ResponseDTO firmarDocumento(RequestFirmarDTO datosFirmar, String pUserName);
    public ResponseDTO verificarFirmasPdf(String pdfBase64);
}
