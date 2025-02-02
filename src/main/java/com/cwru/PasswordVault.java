package com.cwru;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordVault {
  Pattern pattern = Pattern.compile("(.+):([^:]+)$");
  private Map<String, String> map;
  private byte[] salt;
  private final String ALGORITHM = "AES";
  private final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
  private final int ITERATIONS = 3_000_000;
  private final int KEY_LENGTH = 256;

  private Cipher cipher;
  private SecretKey secretKey;

  public PasswordVault(String filename, String password) throws PasswordVaultInitException {
    try {
      this.map = loadFile(filename);
      this.cipher = Cipher.getInstance("AES");
      this.secretKey = generateSecretKey(password, salt);
    } catch (FileNotFoundException e) {
      try {
        createFile(filename);
      } catch (IOException | CryptoException ex) {
        throw new PasswordVaultInitException("Error creating new password file", ex);
      }
      throw new PasswordVaultInitException("Password file not found, new file created", e);
    } catch (PasswordFileParserException e) {
      throw new PasswordVaultInitException("Error parsing password file: " + filename, e);
    } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException e) {
      throw new PasswordVaultInitException("Error generating secret key", e);
    }
  }

  /**
   * Load a file into the password file parser and set up the metadata.
   *
   * <p>Files should be of the form: ``` salt key:value key2:value2 ```
   */
  private Map<String, String> loadFile(String filename)
      throws FileNotFoundException, PasswordFileParserException {
    Map<String, String> map = new HashMap<>();

    try (Stream<String> lines = Files.lines(Paths.get(filename))) {
      Iterator<String> iterator = lines.iterator();

      // Handle the first line (salt)
      if (iterator.hasNext()) {
        salt = (Base64.getDecoder().decode(iterator.next()));
      } else {
        throw new PasswordFileParserException();
      }

      // Process the remaining lines (from second line onwards)
      while (iterator.hasNext()) {
        String line = iterator.next();
        Matcher matcher = pattern.matcher(line);
        if (matcher.matches()) {
          String key = matcher.group(1);
          String value = matcher.group(2);
          map.put(key, value);
        } else {
          throw new PasswordFileParserException();
        }
      }
    } catch (IOException e) {
      throw new FileNotFoundException();
    }

    return map;
  }

  /**
   * Creates a new password file with a verification token.
   *
   * @param filename The name of the file to be created
   * @throws IOException If there's an error writing to the file
   * @throws CryptoException If there's an error during encryption
   */
  private void createFile(String filename) throws IOException, CryptoException {
    String encryptedToken = encrypt("verification_token");
    String fileContent = Base64.getEncoder().encodeToString(salt) + ":" + encryptedToken + "\n";
    Files.write(Paths.get(filename), fileContent.getBytes());
  }

  /**
   * Encrypts a given string using the initialized cipher and secret key.
   *
   * @param strToEncrypt The string to be encrypted
   * @return The encrypted string, Base64 encoded
   * @throws CryptoException If there's an error during the encryption process
   */
  private String encrypt(String strToEncrypt) throws CryptoException {
    try {
      this.cipher.init(Cipher.ENCRYPT_MODE, secretKey);
      return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
    } catch (Exception e) {
      throw new CryptoException();
    }
  }

  /**
   * Decrypts a given string using the initialized cipher and secret key.
   *
   * @param strToDecrypt The Base64 encoded encrypted string to be decrypted
   * @return The decrypted string
   * @throws CryptoException If there's an error during the decryption process
   */
  private String decrypt(String strToDecrypt) throws CryptoException {
    try {
      this.cipher.init(Cipher.DECRYPT_MODE, secretKey);
      return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
    } catch (Exception e) {
      throw new CryptoException();
    }
  }

  /** Sets encrypted password base 64 string */
  public void setPassword(String key, String password) throws CryptoException {
    setPassword(key, encrypt(password));
  }

  /**
   * Retrieves password given key
   *
   * @return null if key-value pair does not exist, else the password
   */
  public Optional<String> getPassword(String key) throws NoSuchElementException, CryptoException {
    if (map.containsKey(key)) return Optional.of(decrypt(map.get(key)));
    return Optional.empty();
  }

  private SecretKeySpec generateSecretKey(String passcode, byte[] salt)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
    KeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
    SecretKey tmp = factory.generateSecret(spec);
    return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
  }

  public class CryptoException extends Exception {}

  public class PasswordFileParserException extends Exception {}

  public class PasswordVaultInitException extends Exception {

    public PasswordVaultInitException(String message) {
      super(message);
    }

    public PasswordVaultInitException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
