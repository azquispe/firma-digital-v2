package com.ganaseguro.firmador.services;

import com.ganaseguro.firmador.dto.RequestFirmarLoteArchivosDTO;
import com.ganaseguro.firmador.dto.RequestFirmarLoteUsuarioDTO;
import com.ganaseguro.firmador.dto.ResponseDTO;

import java.util.List;

public interface IFirmaService {
    public ResponseDTO firmarLoteUsuarios(RequestFirmarLoteUsuarioDTO objLoteUsuarios);
    public ResponseDTO firmarLoteArchivos(RequestFirmarLoteArchivosDTO objLoteArchivo);
    public ResponseDTO verificarFirmasPdf(String pdfBase64);
}
