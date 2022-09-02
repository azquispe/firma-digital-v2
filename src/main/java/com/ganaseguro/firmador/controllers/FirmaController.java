package com.ganaseguro.firmador.controllers;

import com.azure.storage.blob.BlobClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.BlobItem;
import com.ganaseguro.firmador.dto.*;
import com.ganaseguro.firmador.services.IFirmaService;
import com.ganaseguro.firmador.utils.constantes.ConstDiccionarioMensajeFirma;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileWriter;
import java.util.HashMap;
import java.util.Map;


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

            //Create a unique name for the container
            String containerName = "quickstartblobs" + java.util.UUID.randomUUID();

            // Create the container and return a container client object
            BlobContainerClient containerClient = blobServiceClient.createBlobContainer(containerName);

            // Create a local file in the ./data/ directory for uploading and downloading
            String localPath = "./data/";
            String fileName = "quickstart" + java.util.UUID.randomUUID() + ".txt";
            File localFile = new File(localPath + fileName);

            // Write text to the file
            FileWriter writer = new FileWriter(localPath + fileName, true);
            writer.write("Hello, World!");
            writer.close();

            // Get a reference to a blob
            BlobClient blobClient = containerClient.getBlobClient(fileName);

            System.out.println("\nUploading to Blob storage as blob:\n\t" + blobClient.getBlobUrl());

            // Upload the blob
            blobClient.uploadFromFile(localPath + fileName);

            Map<String, Object> response = new HashMap<>();
            response.put("codigoMensaje", "0");
            response.put("mensaje", "Hola este es una prueba contenedor: "+blobClient.getBlobUrl());
            return new ResponseEntity<Map<String, Object>>(response, HttpStatus.OK);
        }catch (Exception ex){
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
