package com.cwru;

import com.cwru.PasswordVault.PasswordVaultInitException;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class PasswordManager {
  public static final String PASSWORD_FILE = "passwords.txt";

  public static void main(String[] args) throws FileNotFoundException {
    Scanner scanner = new Scanner(System.in);
    PasswordVault fileParser;

    System.out.print("Enter the passcode to access your passwords: ");
    String passcode = scanner.nextLine();
    try {
      fileParser = new PasswordVault(PASSWORD_FILE, passcode);
    } catch (PasswordVaultInitException e) {
      System.out.println("Error opening vault, possibly incorrect password.");
      scanner.close();
      System.exit(1);
      return;
    }

    while (true) {
      System.out.println("a : Add Password");
      System.out.println("r : Read Password");
      System.out.println("q : Quit");
      System.out.print("Enter choice: ");
      String choice = scanner.nextLine();

      try {
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
              String readPassword = fileParser.getPassword(readLabel).get();
              System.out.println("Found: " + readPassword);
            } catch (Exception e) {
              System.out.println("Error reading password: " + e.getMessage());
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
        System.out.println();
      } catch (Exception e) {
        System.out.println("Error: " + e.getMessage());
      }
    }
  }
}
