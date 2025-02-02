package com.cwru;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Iggy {
  private static final String FILE_NAME = "passwords.txt";
  private static final String ALGORITHM = "AES";
  private static final String SECRET_KEY_ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final int ITERATIONS = 30;
  private static final int KEY_LENGTH = 256;
  private static final int SALT_LENGTH = 16;

  private static SecretKeySpec secretKey;
  private static byte[] salt;

  public static void main(String[] args) throws Exception {
    Scanner scanner = new Scanner(System.in);

    // Check if password file exists
    if (!Files.exists(Paths.get(FILE_NAME))) {
      System.out.print("Enter the passcode to access your passwords: ");
      String passcode = scanner.nextLine();
      salt = generateSalt();
      secretKey = generateSecretKey(passcode, salt);
      createPasswordFile(passcode);
      System.out.println("No password file detected. Creating a new password file.");
    } else {
      System.out.print("Enter the passcode to access your passwords: ");
      String passcode = scanner.nextLine();
      // This method includes checking against the password
      loadPasswordFile(passcode);
    }

    // Main loop
    while (true) {
      System.out.println("a : Add Password");
      System.out.println("r : Read Password");
      System.out.println("q : Quit");
      System.out.print("Enter choice: ");
      String choice = scanner.nextLine();

      switch (choice) {
        case "a":
          System.out.print("Enter label for password: ");
          String label = scanner.nextLine();
          System.out.print("Enter password to store: ");
          String password = scanner.nextLine();
          addPassword(label, password);
          break;
        case "r":
          System.out.print("Enter label for password: ");
          String readLabel = scanner.nextLine();
          String readPassword = readPassword(readLabel);
          if (readPassword != null) {
            System.out.println("Found: " + readPassword);
          } else {
            System.out.println("Password not found.");
          }
          break;
        case "q":
          System.out.println("Quitting");
          scanner.close();
          System.exit(0);
          break;
        default:
          System.out.println("Invalid choice. Please try again.");
      }
    }
  }

  private static byte[] generateSalt() {
    SecureRandom random = new SecureRandom();
    byte[] salt = new byte[SALT_LENGTH];
    random.nextBytes(salt);
    return salt;
  }

  private static SecretKeySpec generateSecretKey(String passcode, byte[] salt)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory factory = SecretKeyFactory.getInstance(SECRET_KEY_ALGORITHM);
    KeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
    SecretKey tmp = factory.generateSecret(spec);
    return new SecretKeySpec(tmp.getEncoded(), ALGORITHM);
  }

  private static void createPasswordFile(String passcode) throws Exception {
    String token = "verification_token";
    String encryptedToken = encrypt(token);
    String fileContent = Base64.getEncoder().encodeToString(salt) + ":" + encryptedToken + "\n";
    Files.write(Paths.get(FILE_NAME), fileContent.getBytes());
  }

  private static void loadPasswordFile(String passcode) throws Exception {
    String fileContent = new String(Files.readAllBytes(Paths.get(FILE_NAME)));
    String[] parts = fileContent.split("\n")[0].split(":");
    salt = Base64.getDecoder().decode(parts[0]);
    secretKey = generateSecretKey(passcode, salt);
    String decryptedToken = decrypt(parts[1]);
    if (!decryptedToken.equals("verification_token")) {
      System.out.println("Incorrect passcode.");
      System.exit(1);
    }
  }

  private static void addPassword(String label, String password) throws Exception {
    String encryptedPassword = encrypt(password);
    String fileContent = label + ":" + encryptedPassword + "\n";
    Files.write(
        Paths.get(FILE_NAME), fileContent.getBytes(), java.nio.file.StandardOpenOption.APPEND);
  }

  private static String readPassword(String label) throws Exception {
    String fileContent = new String(Files.readAllBytes(Paths.get(FILE_NAME)));
    String[] lines = fileContent.split("\n");
    for (String line : lines) {
      String[] parts = line.split(":");
      if (parts[0].equals(label)) {
        return decrypt(parts[1]);
      }
    }
    return null;
  }

  private static String encrypt(String strToEncrypt) throws Exception {
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
  }

  private static String decrypt(String strToDecrypt) throws Exception {
    Cipher cipher = Cipher.getInstance(ALGORITHM);
    cipher.init(Cipher.DECRYPT_MODE, secretKey);
    return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
  }
}
