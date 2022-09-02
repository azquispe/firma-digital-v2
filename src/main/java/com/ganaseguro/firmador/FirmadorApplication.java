package com.ganaseguro.firmador;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Azure blob storage v12 SDK quickstart
 */
import com.azure.storage.blob.*;
import com.azure.storage.blob.models.*;
import java.io.*;
@SpringBootApplication
public class FirmadorApplication  {

    public static void main(String[] args) {

        SpringApplication.run(FirmadorApplication.class, args);

        // GENERAR LLAVE PRIVADA Y PUBLICA DESDE JAVA
        /*try{
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048); KeyPair kp = kpg.generateKeyPair();
            System.out.println ("-----BEGIN PRIVATE KEY-----");
            System.out.println (Base64.getMimeEncoder().encodeToString( kp.getPrivate().getEncoded()));
            System.out.println ("-----END PRIVATE KEY-----");
            System.out.println ("-----BEGIN PUBLIC KEY-----");
            System.out.println (Base64.getMimeEncoder().encodeToString( kp.getPublic().getEncoded()));
            System.out.println ("-----END PUBLIC KEY-----");
        }catch (Exception ex){

        }*/
        //================================================


    }


}
