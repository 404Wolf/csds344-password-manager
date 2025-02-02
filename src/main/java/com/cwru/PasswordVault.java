
package com.cwru;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.regex.*;
import java.util.stream.Stream;

public class PasswordVault {
  private static final String ALGORITHM = "AES";
  private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final int ITERATIONS = 3_000_000;
  private static final int KEY_LENGTH = 256;

  private final Pattern pattern = Pattern.compile("(.+):([^:]+)$");
  private final Map<String, String> map;
  private byte[] salt;
  private final String filename;
  private final Cipher cipher;
  private final SecretKey secretKey;

  /**
   * Initializes the PasswordVault with the given filename and password.
   * 
   * @param filename The name of the password file
   * @param password The master password for encryption/decryption
   * @throws PasswordVaultInitException If there's an error during initialization
   */
  public PasswordVault(String filename, String password) throws PasswordVaultInitException {
    this.filename = filename;
    try {
      this.map = loadFile(filename);
      this.cipher = Cipher.getInstance("AES");
      this.secretKey = generateSecretKey(password, salt);
    } catch (FileNotFoundException e) {
      createNewFile(filename);
      throw new PasswordVaultInitException("Password file not found, new file created", e);
    } catch (Exception e) {
      throw new PasswordVaultInitException("Error initializing PasswordVault", e);
    }
  }

  /**
   * Loads the password file and parses its contents.
   * 
   * @param filename The name of the file to load
   * @return A map of the parsed key-value pairs
   * @throws IOException                 If there's an error reading the file
   * @throws PasswordFileParserException If there's an error parsing the file
   *                                     contents
   */
  private Map<String, String> loadFile(String filename) throws IOException, PasswordFileParserException {
    Map<String, String> map = new HashMap<>();

    try (Stream<String> lines = Files.lines(Paths.get(filename))) {
      Iterator<String> iterator = lines.iterator();

      if (!iterator.hasNext()) {
        throw new PasswordFileParserException("File is empty");
      }

      salt = Base64.getDecoder().decode(iterator.next());

      while (iterator.hasNext()) {
        String line = iterator.next();
        Matcher matcher = pattern.matcher(line);
        if (matcher.matches()) {
          map.put(matcher.group(1), matcher.group(2));
        } else {
          throw new PasswordFileParserException("Invalid line format: " + line);
        }
      }
    }

    return map;
  }

  /**
   * Writes the current state of the password vault to the file.
   * 
   * @throws IOException If there's an error writing to the file
   */
  public void dumpFile() throws IOException {
    try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(filename))) {
      writer.write(Base64.getEncoder().encodeToString(salt));
      writer.newLine();

      for (Map.Entry<String, String> entry : map.entrySet()) {
        writer.write(entry.getKey() + ":" + entry.getValue());
        writer.newLine();
      }
    }
  }

  /**
   * Creates a new password file with a verification token.
   * 
   * @param filename The name of the file to be created
   * @throws PasswordVaultInitException If there's an error creating the file
   */
  private void createNewFile(String filename) throws PasswordVaultInitException {
    try {
      salt = generateSalt();
      String encryptedToken = encrypt("verification_token");
      Files.write(Paths.get(filename),
          (Base64.getEncoder().encodeToString(salt) + "\nverification:" + encryptedToken).getBytes());
    } catch (Exception e) {
      throw new PasswordVaultInitException("Error creating new password file", e);
    }
  }

  /**
   * Encrypts a given string using the initialized cipher and secret key.
   * 
   * @param strToEncrypt The string to be encrypted
   * @return The encrypted string, Base64 encoded
   * @throws GeneralSecurityException If there's an error during encryption
   */
  private String encrypt(String strToEncrypt) throws GeneralSecurityException {
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
  }

  /**
   * Decrypts a given string using the initialized cipher and secret key.
   * 
   * @param strToDecrypt The Base64 encoded encrypted string to be decrypted
   * @return The decrypted string
   * @throws GeneralSecurityException If there's an error during decryption
   */
  private String decrypt(String strToDecrypt) throws GeneralSecurityException {
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
  }

  /**
   * Sets an encrypted password for a given key.
   * 
   * @param key      The key associated with the password
   * @param password The password to be encrypted and stored
   * @throws Exception If there's an error during encryption or file writing
   */
  public void setPassword(String key, String password) throws Exception {
    map.put(key, encrypt(password));
    dumpFile();
  }

  /**
   * Retrieves and decrypts a password for a given key.
   * 
   * @param key The key associated with the password
   * @return An Optional containing the decrypted password, or empty if the key
   *         doesn't exist
   *         or if there's an error during decryption
   */
  public Optional<String> getPassword(String key) {
    try {
      String encryptedPassword = map.get(key);
      if (encryptedPassword == null) {
        return Optional.empty();
      }
      return Optional.of(decrypt(encryptedPassword));
    } catch (GeneralSecurityException e) {
      return Optional.empty();
    }
  }

  /**
   * Generates a secret key from the given password and salt.
   * 
   * @param passcode The password to generate the key from
   * @param salt     The salt to use in key generation
   * @return A SecretKeySpec for use in encryption/decryption
   * @throws NoSuchAlgorithmException If the specified algorithm is not available
   * @throws InvalidKeySpecException  If the given key specification is
   *                                  inappropriate
   */
  private SecretKeySpec generateSecretKey(String passcode, byte[] salt)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
    PBEKeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
    SecretKey tmp = factory.generateSecret(spec);
    return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
  }

  /**
   * Generates a random salt for use in key generation.
   * 
   * @return A byte array containing the generated salt
   */
  private byte[] generateSalt() {
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    return salt;
  }

  /**
   * Exception thrown when there's an error parsing the password file.
   */
  public static class PasswordFileParserException extends Exception {
    public PasswordFileParserException(String message) {
      super(message);
    }
  }

  /**
   * Exception thrown when there's an error initializing the PasswordVault.
   */
  public static class PasswordVaultInitException extends Exception {
    public PasswordVaultInitException(String message) {
      super(message);
    }

    public PasswordVaultInitException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
