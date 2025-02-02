package com.cwru;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordVault {
  private static final String ALGORITHM = "AES";
  private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final String VERIFICATION_TOKEN = "verification_token";
  private static final int ITERATIONS = 300_000;
  private static final int KEY_LENGTH = 256;

  private final Pattern pattern = Pattern.compile("(.+):([^:]+)$");
  private final Map<String, String> map;
  private byte[] salt;
  private String filename;
  private Cipher cipher;
  private SecretKey secretKey;
  public final boolean freshFile;

  /**
   * Initializes the PasswordVault with the given filename and password.
   *
   * @param filename The name of the password file
   * @param password The master password for encryption/decryption
   * @throws PasswordVaultInitException If there's an error during initialization
   */
  public PasswordVault(String filename, String password) throws PasswordVaultInitException {
    this.filename = filename;
    this.map = new HashMap<>();

    try {
      this.cipher = Cipher.getInstance(ALGORITHM);
      this.salt = generateSalt();
      this.secretKey = generateSecretKey(password, salt);

      if (Files.exists(Paths.get(filename))) {
        this.freshFile = false;
        loadExistingFile(password);
      } else {
        this.freshFile = true;
        createNewFile();
      }
    } catch (Exception e) {
      throw new PasswordVaultInitException("Error initializing PasswordVault", e);
    }
  }

  /**
   * Loads an existing password file and decrypts its contents.
   */
  private void loadExistingFile(String password)
      throws IOException,
      PasswordFileParserException,
      GeneralSecurityException,
      PasswordVaultInitException {
    try (Stream<String> lines = Files.lines(Paths.get(filename))) {
      Iterator<String> iterator = lines.iterator();

      if (!iterator.hasNext()) {
        throw new PasswordFileParserException("File is empty");
      }

      String[] saltAndToken = iterator.next().split(":");
      this.salt = Base64.getDecoder().decode(saltAndToken[0]);
      this.secretKey = generateSecretKey(password, salt);
      String decryptedToken = decrypt(saltAndToken[1]);
      if (!decryptedToken.equals(VERIFICATION_TOKEN)) {
        throw new PasswordVaultInitException("Incorrect password");
      }

      while (iterator.hasNext()) {
        String line = iterator.next();
        Matcher matcher = pattern.matcher(line);
        if (matcher.matches()) {
          this.map.put(matcher.group(1), matcher.group(2));
        } else {
          throw new PasswordFileParserException("Invalid line format: " + line);
        }
      }
    }
  }

  /**
   * Writes the current state of the password vault to the file.
   *
   * @throws IOException If there's an error writing to the file
   */
  public void dumpFile() throws IOException, GeneralSecurityException {
    try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(filename))) {
      writer.write(Base64.getEncoder().encodeToString(salt) + ":" + encrypt(VERIFICATION_TOKEN));
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
   * @throws PasswordVaultInitException If there's an error creating the file
   */
  private void createNewFile() throws PasswordVaultInitException {
    try {
      String encryptedToken = encrypt(VERIFICATION_TOKEN);
      Files.write(
          Paths.get(filename),
          (Base64.getEncoder().encodeToString(this.salt) + ":" + encryptedToken).getBytes());
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
    if (map.containsKey(key)) {
      System.out.println("You are overwriting a password! Aborting.");
      return;
    }
    map.put(key, encrypt(password));
    dumpFile();
  }

  /**
   * Retrieves and decrypts a password for a given key.
   *
   * @param key The key associated with the password
   * @return An Optional containing the decrypted password, or empty if the key
   *         doesn't exist or if
   *         there's an error during decryption
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
