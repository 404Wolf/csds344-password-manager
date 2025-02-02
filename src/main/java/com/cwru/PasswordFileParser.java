package com.cwru;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class PasswordFileParser {
  Pattern pattern = Pattern.compile("(.+):([^:]+)$");
  private Map<String, String> map;
  private String salt;
  private String token;

  public void PassswordFileParser(String filename, String salt, String token)
      throws FileNotFoundException, PasswordFileParserException {
    this.map = loadFile(filename);
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
        salt = iterator.next();
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
   * Returns the salt for the given key
   *
   * @return null if key does not exist, else the salt
   */
  public final String getSalt(String key) {
    return this.salt;
  }

  /**
   * Returns the salt for the given key
   *
   * @return null if key does not exist, else the salt
   */
  public final void setSalt(String key) {}

  /**
   * Returns the token used for encryption
   *
   * @return null if key does not exist, else the salt
   */
  protected final String getToken(String key) {
    return token;
  }

  /** Set the token used for encrytpion */
  public final void setToken(String token) {
    this.token = token;
  }

  /** Sets encrypted password base 64 string */
  public void setPassword(String key, String password) throws AlreadyExistsException {
    map.put(key, password);
  }

  /**
   * Gets raw unencrypted password base64 string
   *
   * @return optional empty if key does not exist, else the password
   */
  public Optional<String> getPassword(String key, String password) {
    return Optional.of(map.get(key));
  }

  public static class AlreadyExistsException extends Exception {}
  ;

  public static class PasswordFileParserException extends Exception {}
}
