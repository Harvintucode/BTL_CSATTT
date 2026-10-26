package vn.novabank;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;
import vn.novabank.config.JwtService;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {
  private static final String SECRET = "unit-test-secret-with-at-least-32-bytes!!";

  @Test void tokenRoundTripKeepsIdentityAndRole() {
    JwtService jwt = new JwtService(SECRET);
    Claims c = jwt.parse(jwt.create(7, "huy", "CUSTOMER"));
    assertEquals("7", c.getSubject());
    assertEquals("huy", c.get("username", String.class));
    assertEquals("CUSTOMER", c.get("role", String.class));
  }

  @Test void shortSecretIsRejected() {
    assertThrows(IllegalArgumentException.class, () -> new JwtService("too-short"));
  }

  @Test void tokenSignedWithAnotherKeyIsRejected() {
    String token = new JwtService("another-secret-with-at-least-32-bytes!!!").create(1, "huy", "ADMIN");
    assertThrows(Exception.class, () -> new JwtService(SECRET).parse(token));
  }

  @Test void tamperedTokenIsRejected() {
    JwtService jwt = new JwtService(SECRET);
    String token = jwt.create(1, "huy", "CUSTOMER");
    String tampered = token.substring(0, token.length() - 2) + (token.endsWith("AA") ? "BB" : "AA");
    assertThrows(Exception.class, () -> jwt.parse(tampered));
  }
}
