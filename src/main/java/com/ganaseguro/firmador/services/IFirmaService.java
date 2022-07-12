package com.ganaseguro.firmador.services;

import com.ganaseguro.firmador.dto.*;
import jacobitus.token.Token;

public interface IFirmaService {


    public ResponseDto firmar(RequestFirmarDto requestFirmarDto);

    public ResponseDto verificarFirmasPdf(String pdfBase64);

    public ResponseDto obtieneInformacionCertificado(UsuariosFirmantesDto usuariosFirmantesDto);


}
