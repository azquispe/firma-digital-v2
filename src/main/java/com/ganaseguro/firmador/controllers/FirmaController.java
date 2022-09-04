package com.ganaseguro.firmador.controllers;


import com.azure.core.http.rest.PagedIterable;
import com.ganaseguro.firmador.dto.*;
import com.ganaseguro.firmador.services.IFirmaService;
import com.ganaseguro.firmador.utils.constantes.ConstDiccionarioMensajeFirma;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.ResourceUtils;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileWriter;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;


import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import java.io.*;

@CrossOrigin(origins = "*", allowedHeaders = "*")
@RestController
@RequestMapping("/api/firma")
public class FirmaController {

    @Autowired
    private IFirmaService iFirmaService;

    @Value("${storage.conection}")
    private String connectStr;



    @GetMapping("/v1/prueba")
    public ResponseEntity<?> prueba(){
        // ref documentación
        //https://docs.microsoft.com/es-es/azure/storage/blobs/storage-quickstart-blobs-java?tabs=powershell%2Cenvironment-variable-windows
        try{

            // Create a BlobServiceClient object which will be used to create a container client
            BlobServiceClient blobServiceClient = new BlobServiceClientBuilder().connectionString(connectStr).buildClient();

            BlobContainerClient containerClient = blobServiceClient.getBlobContainerClient("cont-firma-digital");
            BlobClient blobCertificado = containerClient.getBlobClient("ABEL.p12");

            ClassLoader classLoader = this.getClass().getClassLoader();


            File p12 = new File("./home/site/wwwroot/softoken");
            new FileWriter(p12);

            Map<String, Object> response = new HashMap<>();


            /*if(!file.exists())
            {
                response.put("codigoMensaje", "0");
                response.put("mensaje", "o se pudo crear directorio0 temporal ");
                return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
            }
            blobCertificado.downloadToFile(file.toString());*/

            response.put("codigoMensaje", "0");
            response.put("mensaje", "holaaaaa ");
            return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
        }catch (Exception ex ){
            Map<String, Object> response = new HashMap<>();
            response.put("codigoMensaje", "2000");
            response.put("mensaje", ex.toString());
            return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
        }


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
    public ResponseEntity<?> verificarFirmaPdf(@RequestBody PdfBase64Dto archivoAVerificar) {

        Map<String, Object> response = new HashMap<>();
        ResponseDto result = iFirmaService.verificarFirmasPdf(archivoAVerificar.getPdfBase64());
        response.put("codigoMensaje", result.getCodigo());
        response.put("mensaje", result.getMensaje());
        response.put("firmas", result.getElementoGenerico());
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }

    @PostMapping("/v1/obtiene-informacion-certificado")
    public ResponseEntity<?> obtieneInformacionCertificado(@RequestBody UsuariosFirmantesDto usuariosFirmantesDto) {

        Map<String, Object> response = new HashMap<>();
        ResponseDto result = iFirmaService.obtieneInformacionCertificado(usuariosFirmantesDto);
        response.put("codigoMensaje", result.getCodigo());
        response.put("mensaje", result.getMensaje());
        response.put("data_token", result.getElementoGenerico());
        return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
    }
}
