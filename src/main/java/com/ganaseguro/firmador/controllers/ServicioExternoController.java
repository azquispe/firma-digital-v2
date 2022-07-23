package com.ganaseguro.firmador.controllers;


import com.ganaseguro.firmador.dto.RequestConsultaSegipDto;
import com.ganaseguro.firmador.dto.RequestFirmarDto;
import com.ganaseguro.firmador.dto.ResponseDto;
import com.ganaseguro.firmador.utils.constantes.ConstDiccionarioMensajeFirma;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.sun.xml.bind.v2.runtime.reflect.opt.Const;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
@RequestMapping("/api/servicios-externos")
public class ServicioExternoController {

    @PostMapping("/v1/consultas-segip")
    public ResponseEntity<?> consultasSegip(@RequestBody RequestConsultaSegipDto requestConsultaSegipDto) {
        Map<String, Object> resp = new HashMap<>();
        try{


        RestTemplate restTemplate = new RestTemplate();
        Map<String,Object> access_and_key_code = new HashMap<>();
        access_and_key_code.put("client_key", "$2a$10$Ft6UCTo6ovMcGD/d5uJF.eq3uTqeiU0V.VRtHpWRjceNKHw9o01CO");
        access_and_key_code.put("access_code", "Ganaseguros");
        Map<String,Object> data_risk = new HashMap<>();
        data_risk.put("data", access_and_key_code);

        String fooResourceUrl = "https://api.bg.com.bo/openapi-stage/v1";
        ResponseEntity<String> response = restTemplate.postForEntity(fooResourceUrl + "/auth",data_risk, String.class);

        JsonObject data = new Gson().fromJson( response.getBody(), JsonObject.class);
        JsonObject token = (JsonObject) data .get("data");
        String acces_token =  token.get("access_token").toString();


            HttpHeaders headers = new HttpHeaders();
            headers.set("x-fapi-financial-id", "63");
            headers.set("token", acces_token);

            Map<String,Object> map_body = new HashMap<>();
            map_body.put("ci",requestConsultaSegipDto.getCi());
            map_body.put("documentCity",requestConsultaSegipDto.getDocumentCity());
            map_body.put("birthdate",requestConsultaSegipDto.getBirthdate());
            Map<String,Object> dataRequest = new HashMap<>();
            dataRequest.put("data",map_body);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(dataRequest, headers);
            RestTemplate restTemplate2 = new RestTemplate();
        ResponseEntity<String> datospersona = restTemplate2.postForEntity(fooResourceUrl + "/accounts/validations/segip",entity, String.class);





            resp.put("codigoMensaje", ConstDiccionarioMensajeFirma.COD1000);
            resp.put("mensaje", "Otención de datos de Segip");
            resp.put("data", datospersona);
            return new ResponseEntity<Map<String, Object>>(resp, HttpStatus.OK);

        }catch (Exception ex){
            resp.put("codigoMensaje", ConstDiccionarioMensajeFirma.COD2000);
            resp.put("mensaje", ex.toString());
            return new ResponseEntity<Map<String, Object>>(resp, HttpStatus.OK);
        }

    }
}
