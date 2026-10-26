package vn.novabank;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import vn.novabank.config.LabProperties;

import static org.junit.jupiter.api.Assertions.*;

class LabConfigurationTest {
  @Test void passwordsAreHashedNotStoredAsPlaintext() {
    var encoder = new BCryptPasswordEncoder(4);
    String hash = encoder.encode("123456");
    assertNotEquals("123456", hash);
    assertTrue(encoder.matches("123456", hash));
    assertFalse(encoder.matches("wrong", hash));
  }

  @Test void vulnerableModeIsOnlyEnabledByExplicitValue() {
    assertTrue(new LabProperties("vulnerable").vulnerable());
    assertTrue(new LabProperties("VULNERABLE").vulnerable());
    assertFalse(new LabProperties("fixed").vulnerable());
    assertFalse(new LabProperties(null).vulnerable());
    assertFalse(new LabProperties("").vulnerable());
    assertFalse(new LabProperties("typo").vulnerable());
  }
}
