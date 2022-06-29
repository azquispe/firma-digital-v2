package com.ganaseguro.firmador.services;


import com.ganaseguro.firmador.dto.ResponseDto;

public interface IEncryptDecryptService {

        //public ResponseDto encryptMessage(String plainText);
        public ResponseDto decryptMessage(String encryptedMessgae);

}
