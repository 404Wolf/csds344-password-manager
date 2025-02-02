package com.cwru;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager {
  public static final String FILE_NAME = "passwords.txt";
  public static final String ALGORITHM = "AES";
  public static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
  public static final int ITERATIONS = 30;
  public static final int KEY_LENGTH = 256;
  public static final int SALT_LENGTH = 16;

  private static SecretKeySpec secretKey;

  public static void main(String[] args) {
    System.out.println("Hello World!");
  }

  public static String encrypt(String strToEncrypt) throws Exception {
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
  }

  public static String decrypt(String strToDecrypt) throws Exception {
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
  }
}
