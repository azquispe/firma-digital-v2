package com.ganaseguro.firmador.controllers;
import com.ganaseguro.firmador.dto.RequestFirmarLoteArchivosDTO;
import com.ganaseguro.firmador.dto.RequestFirmarLoteUsuarioDTO;
import com.ganaseguro.firmador.dto.ResponseDTO;
import com.ganaseguro.firmador.dto.UsuariosFirmantesDTO;
import com.ganaseguro.firmador.services.IFirmaService;
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

    @GetMapping("/prueba")
    public String toString() {
        return "hola Mundo";
    }

    @PostMapping("/firmar-lote-archivos")
    public ResponseEntity<?> firmaLoteArchivo(@RequestBody RequestFirmarLoteArchivosDTO objFirmaLoteArchivo) {

        Map<String, Object> response = new HashMap<>();

            ResponseDTO result =  iFirmaService.firmarLoteArchivos (objFirmaLoteArchivo);
            response.put("mensaje",result.getMensaje());
            response.put("finalizado", result.isFinalizado());
            response.put("pdf(s)_firmado(s)",result.getElementoGenerico());

        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }

    @PostMapping("/firmar-lote-usuarios")
    public ResponseEntity<?> firmaLoteUsuarios(@RequestBody RequestFirmarLoteUsuarioDTO objUsuarioFirmantesMasivoDto) {

        Map<String, Object> response = new HashMap<>();
        ResponseDTO result =  iFirmaService.firmarLoteUsuarios (objUsuarioFirmantesMasivoDto);
        response.put("mensaje",result.getMensaje());
        response.put("finalizado", result.isFinalizado());
        response.put("pdf_firmado",result.getElementoGenerico());
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }


    /*@PostMapping("/verirficar-firma-pdf")
    public ResponseEntity<?> toString(@RequestBody RequestFirmarDTO objFirmaDto) {

        Map<String, Object> response = new HashMap<>();
        try{
            ResponseDTO result =  iFirmaService.verificarFirmasPdf(objFirmaDto.getPdfBase64());
            response.put("mensaje",result.getMensaje());
            response.put("finalizado", result.isFinalizado());
            response.put("firmas",result.getElementoGenerico());
        }catch (Exception ex){
            response.put("mensaje", ex.toString());
            response.put("finalizado", false);
        }
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }*/
}
