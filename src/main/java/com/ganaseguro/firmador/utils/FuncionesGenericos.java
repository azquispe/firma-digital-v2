package com.ganaseguro.firmador.utils;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class FuncionesGenericos {
    public static String pdfToBase64(String pPathFile) {
        try {
            byte[] input_file = Files.readAllBytes(Paths.get(pPathFile));
            byte[] encodedBytes = Base64.getEncoder().encode(input_file);
            return  new String(encodedBytes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}
