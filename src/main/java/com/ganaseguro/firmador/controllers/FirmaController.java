package com.ganaseguro.firmador.controllers;

import com.ganaseguro.firmador.dto.*;
import com.ganaseguro.firmador.services.IFirmaService;
import com.ganaseguro.firmador.utils.constantes.ConstDiccionarioMensajeFirma;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;


@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
@RequestMapping("/api/firma")
public class FirmaController {

    @Autowired
    private IFirmaService iFirmaService;


    @PostMapping("/v1/firmar-lote-archivos")
    public ResponseEntity<?> firmaLoteArchivo(@RequestBody RequestFirmarLoteArchivosDto objFirmaLoteArchivo) {

        Map<String, Object> response = new HashMap<>();
        ResponseDto result = iFirmaService.firmarLoteArchivos(objFirmaLoteArchivo);
        response.put("codigoMensaje", result.getCodigo());
        response.put("mensaje", result.getMensaje());
        response.put("pdfs_firmados", result.getElementoGenerico());
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }

    @PostMapping("/v1/firmar-lote-usuarios")
    public ResponseEntity<?> firmaLoteUsuarios(@RequestBody RequestFirmarLoteUsuarioDto objUsuarioFirmantesMasivoDto) {

        Map<String, Object> response = new HashMap<>();
        ResponseDto result = iFirmaService.firmarLoteUsuarios(objUsuarioFirmantesMasivoDto);
        response.put("codigoMensaje", result.getCodigo());
        response.put("mensaje", result.getMensaje());
        response.put("pdf_firmado", result.getElementoGenerico());
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }

    @PostMapping("/v1/firmar")
    public ResponseEntity<?> firmar(@RequestBody RequestFirmarDto requestFirmarDto) {

        Map<String, Object> response = new HashMap<>();
        ResponseDto result = iFirmaService.firmar(requestFirmarDto);
        response.put("codigoMensaje", result.getCodigo());
        response.put("mensaje", result.getMensaje());
        if(result.getCodigo().equals(ConstDiccionarioMensajeFirma.COD1000))
            response.put("pdfs_firmados", result.getElementoGenerico());
            else
            response.put("log_errores", result.getElementoGenerico());

        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }
    @PostMapping("/v1/verificar-firma-pdf")
    public ResponseEntity<?> toString(@RequestBody PdfBase64Dto archivoAVerificar) {

        Map<String, Object> response = new HashMap<>();
        ResponseDto result = iFirmaService.verificarFirmasPdf(archivoAVerificar.getPdfBase64());
        response.put("codigoMensaje", result.getCodigo());
        response.put("mensaje", result.getMensaje());
        response.put("firmas", result.getElementoGenerico());
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }

    @PostMapping("/v1/obtiene-informacion-certificado")
    public ResponseEntity<?> toString(@RequestBody UsuariosFirmantesDto usuariosFirmantesDto) {

        Map<String, Object> response = new HashMap<>();
        ResponseDto result = iFirmaService.obtieneInformacionCertificado(usuariosFirmantesDto);
        response.put("codigoMensaje", result.getCodigo());
        response.put("mensaje", result.getMensaje());
        response.put("data_token", result.getElementoGenerico());
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }
}
