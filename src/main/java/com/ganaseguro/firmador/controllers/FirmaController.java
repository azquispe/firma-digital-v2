package com.ganaseguro.firmador.controllers;
import com.ganaseguro.firmador.dto.RequestFirmarDTO;
import com.ganaseguro.firmador.dto.RequestFirmarMasivoDTO;
import com.ganaseguro.firmador.dto.ResponseDTO;
import com.ganaseguro.firmador.dto.UsuariosFirmantesDTO;
import com.ganaseguro.firmador.services.IFirmaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
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

    @PostMapping("/firmar-archivo/{pUserName}")
    public ResponseEntity<?> firmaArchivo(@RequestBody RequestFirmarDTO objFirmaDto, @PathVariable String pUserName) {

        Map<String, Object> response = new HashMap<>();
        try{
            ResponseDTO result =  iFirmaService.firmarDocumento (objFirmaDto, pUserName);
            response.put("mensaje",result.getMensaje());
            response.put("finalizado", result.isFinalizado());
            response.put("pdf_firmado",result.getElementoGenerico());
        }catch (Exception ex){
            response.put("mensaje", ex.toString());
            response.put("finalizado", false);
        }
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }

    @PostMapping("/firmar-archivo-masivo")
    public ResponseEntity<?> firmaArchivoMasivo(@RequestBody RequestFirmarMasivoDTO objUsuarioFirmantesMasivoDto) {

        Map<String, Object> response = new HashMap<>();
        try{

            String base64= objUsuarioFirmantesMasivoDto.getPdfBase64();

            for ( UsuariosFirmantesDTO objFirmantes : objUsuarioFirmantesMasivoDto.getLstUsuarioFirmantes() ) {
                ResponseDTO result =  iFirmaService.firmarDocumentoMasivo (base64, objFirmantes.getUserName(), objFirmantes.getPin());
                base64 = result.getElementoGenerico().toString();
            }

            response.put("mensaje","Firmado Masivo Exitoso");
            response.put("finalizado", true);
            response.put("pdf_firmado",base64);
        }catch (Exception ex){
            response.put("mensaje", ex.toString());
            response.put("finalizado", false);
        }
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }

    @PostMapping("/verirficar-firma-pdf")

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
    }
}
