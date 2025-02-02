package com.cwru;

import java.util.Base64;
import java.util.NoSuchElementException;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class PasswordManager {
  public static final String FILE_NAME = "passwords.txt";
  public static void main(String[] args) throws FileNotFoundException {
    Scanner scan = new Scanner(System.in);
    PasswordFileParserEnc fileParser;

    System.out.print("Enter the passcode to access your passwords: ");
    String passcode = scanner.nextLine();
    fileParser = new PasswordFileParserEnc(FILE_NAME, passcode);

    while (true) {
      System.out.println("a : Add Password");
      System.out.println("r : Read Password");
      System.out.println("q : Quit");
      System.out.print("Enter choice: ");
      String choice = scanner.nextLine();

      switch (choice) {
        case "a":
          System.out.print("Enter label for password: ");
          String writeLabel = scanner.nextLine();
          System.out.print("Enter password to store: ");
          String password = scanner.nextLine();
          fileParser.setPassword(writeLabel, password);
          break;
        case "r":
            System.out.print("Enter label for password: ");
            String readLabel = scanner.nextLine();
            try {
              String readPassword = fileParser.getPassword(readLabel);
              System.out.println("Found: " + readPassword);
            } catch (NoSuchElementException e) {
              continue; // error handled
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
}
