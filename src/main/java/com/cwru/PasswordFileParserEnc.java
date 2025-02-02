package com.cwru;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class PasswordFileParserEnc extends PasswordFileParser {
  private final String ALGORITHM = "AES";
  private final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
  private final int ITERATIONS = 30;
  private final int KEY_LENGTH = 256;
  private final int SALT_LENGTH = 16;

  private Cipher cipher;
  private SecretKey secretKey;

  @Override
  public void PassswordFileParser(String filename, String password) {
    try {
      super.PassswordFileParser(filename, password);
    } catch (FileNotFoundException e) {
      System.out.println("No password file detected. Creating a new password file.");
      createFile(filename);
    } catch (PasswordFileParserException e) {
      System.out.printf("Error while parsing %s!", filename);
      break;
    } finally {
      this.cipher = Cipher.getInstance("AES");
      this.secretKey = generateSecretKey(filename, generateSalt(filename));
    }
  }

  private String createFile(String filename) {
    String encryptedToken = encrypt("verification_token");
    String fileContent = Base64.getEncoder().encodeToString(this.getSalt()) + ":" + encryptedToken + "\n";
    Files.write(Paths.get(filename), fileContent.getBytes());
  }

  private String encrypt(String strToEncrypt) throws Exception {
    this.cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
  }

  private String decrypt(String strToDecrypt) {
    this.cipher.init(Cipher.DECRYPT_MODE, secretKey);
    return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
  }

  /**
   * Sets encrypted password base 64 string
  */
  public void setPassword(String key, String password) throws AlreadyExistsException {
    super.setPassword(key, encrypt(password));
  }

  /**
   * Retrieves password given key
   * @return null if key-value pair does not exist, else the password
   */
  public String getPassword(String key, String password) throws NoSuchElementException {
    return decrypt(super.getPassword(key, password).orElseThrow(() -> new NoSuchElementException()));
  }

  private byte[] generateSalt() {
    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[SALT_LENGTH];
    random.nextBytes(salt);
    return salt;
  }
  
  private SecretKeySpec generateSecretKey(String passcode, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
    KeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
    SecretKey tmp = factory.generateSecret(spec);
    return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
  }
}
