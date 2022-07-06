package com.ganaseguro.firmador.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

// AUN NO SE USA, PREO ESTA CLASE VA SER PARA MANEJAR SOLO FECHAS
public class FuncionesFechas {
    public static Date ConvertirFormatoYYYYMMDD(String fecha) throws ParseException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        return sdf.parse(fecha);
    }
}
