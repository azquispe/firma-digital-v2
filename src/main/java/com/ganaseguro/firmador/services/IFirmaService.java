package com.ganaseguro.firmador.services;

import com.ganaseguro.firmador.dto.RequestFirmarLoteArchivosDto;
import com.ganaseguro.firmador.dto.RequestFirmarLoteUsuarioDto;
import com.ganaseguro.firmador.dto.ResponseDto;

public interface IFirmaService {


    public ResponseDto firmarLoteUsuarios(RequestFirmarLoteUsuarioDto objLoteUsuarios);
    public ResponseDto firmarLoteArchivos(RequestFirmarLoteArchivosDto objLoteArchivo);
    public ResponseDto verificarFirmasPdf(String pdfBase64);
}
