package com.cwru;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class PasswordFileParser {
  Pattern pattern = Pattern.compile(".*:(.+)");
  private Map<String, String> map;

  public void PassswordFileParser(String filename) {
    // this.map = loadFile(filename);
  }

  private static Map<String, String> loadFile(String filename) throws FileNotFoundException {
    Map<String, String> map = new HashMap<>();
    File myObj = new File(filename);

    try (Stream<String> lines = Files.lines(Paths.get(filename))) {
      lines.forEach(line -> {});

    } catch (IOException e) {
    }

    return map;
  }

  /**
   * Returns the salt for the given key
   *
   * @return null if key does not exist, else the salt
   */
  public final String getSalt(String key) {
    return "";
  }

  /** Sets encrypted password base 64 string */
  public void setPassword(String key, String password) throws AlreadyExistsException {}

  /**
   * Gets raw unencrypted password base64 string
   *
   * @return null if key does not exist, else the password
   */
  public String getPassword(String key, String password) {
    return "";
  }

  public static class AlreadyExistsException extends Exception {}
  ;
}
