package com.cwru;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for the password manager.
 */
public class PasswordManagerTest extends TestCase {
  public PasswordManagerTest(String testName) {
    super(testName);
  }

  public static Test suite() {
    return new TestSuite(PasswordManagerTest.class);
  }

  public void testApp() {
    assertTrue(true);
  }
}
