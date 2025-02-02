package com.cwru;

import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class PasswordManager {
  public static final String FILE_NAME = "passwords.txt";
  public static final String ALGORITHM = "AES";
  public static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
  public static final int ITERATIONS = 30;
  public static final int KEY_LENGTH = 256;
  public static final int SALT_LENGTH = 16;

  private static SecretKeySpec secretKey;
  private static byte[] salt;
  public static void main(String[] args) throws FileNotFoundException {
    Scanner scan = new Scanner(System.in);
    PasswordFileParserCrypto pfp = new PasswordFileParserCrypto();

    // Check if password file exists
    if (!Files.exists(Paths.get(FILE_NAME))) {
      System.out.print("Enter the passcode to access your passwords: ");
      String passcode = scanner.nextLine();
      salt = generateSalt();
      secretKey = generateSecretKey(passcode, salt);
      System.out.println("No password file detected. Creating a new password file.");
      String token = encrypt("verification_token");
      String fileContent = Base64.getEncoder().encodeToString(salt) + ":" + token + "\n";
      Files.write(Paths.get(FILE_NAME), fileContent.getBytes());
  } else {
      System.out.print("Enter the passcode to access your passwords: ");
      
  }
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
