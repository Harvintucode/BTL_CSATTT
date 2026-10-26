package vn.novabank;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.server.ResponseStatusException;
import vn.novabank.config.JwtService;
import vn.novabank.config.LabProperties;
import vn.novabank.repository.SecurityEventRepository;
import vn.novabank.repository.UserRepository;
import vn.novabank.service.AuthService;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class AuthServiceTest {
  private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(4);
  private final JwtService jwt = new JwtService("unit-test-secret-with-at-least-32-bytes!!");
  private UserRepository users;
  private SecurityEventRepository events;

  @BeforeEach void setUp() {
    users = mock(UserRepository.class);
    events = mock(SecurityEventRepository.class);
    when(users.findByUsername("huy")).thenReturn(Optional.of(
      Map.of("id", 1L, "username", "huy", "password_hash", encoder.encode("123456"), "role", "CUSTOMER")));
    // Unstubbed lookups return Optional.empty() (Mockito default for Optional).
  }

  private AuthService service(String mode) { return new AuthService(users, encoder, jwt, events, new LabProperties(mode)); }

  private static int statusOf(Runnable r) {
    try { r.run(); return 200; } catch (ResponseStatusException e) { return e.getStatusCode().value(); }
  }

  @Test void validLoginReturnsBearerTokenAndUser() {
    var result = service("fixed").login("Huy", "123456"); // username is case-insensitive
    assertNotNull(result.get("token"));
    assertEquals("Bearer", result.get("tokenType"));
    @SuppressWarnings("unchecked") var user = (Map<String, Object>) result.get("user");
    assertEquals("CUSTOMER", user.get("role"));
  }

  @Test void fixedModeBlocksAfterFiveFailures() {
    AuthService s = service("fixed");
    for (int i = 0; i < 5; i++) assertEquals(401, statusOf(() -> s.login("huy", "wrong")));
    assertEquals(429, statusOf(() -> s.login("huy", "wrong")));
    assertEquals(429, statusOf(() -> s.login("huy", "123456")), "correct password must not bypass the lock");
    verify(events, atLeastOnce()).add(eq("BRUTE_FORCE_BLOCK"), anyString(), eq("huy"), anyString());
  }

  @Test void unknownUsernamesAreThrottledTheSameWay() {
    AuthService s = service("fixed");
    for (int i = 0; i < 5; i++) assertEquals(401, statusOf(() -> s.login("ghost", "x")));
    assertEquals(429, statusOf(() -> s.login("ghost", "x")));
  }

  @Test void vulnerableModeNeverBlocks() {
    AuthService s = service("vulnerable");
    for (int i = 0; i < 12; i++) assertEquals(401, statusOf(() -> s.login("huy", "wrong")));
    assertEquals(200, statusOf(() -> s.login("huy", "123456")));
  }

  @Test void successfulLoginResetsFailureCounter() {
    AuthService s = service("fixed");
    for (int i = 0; i < 4; i++) assertEquals(401, statusOf(() -> s.login("huy", "wrong")));
    assertEquals(200, statusOf(() -> s.login("huy", "123456")));
    for (int i = 0; i < 4; i++) assertEquals(401, statusOf(() -> s.login("huy", "wrong")));
  }

  @Test void veryLongUsernameDoesNotBreakEventLogging() {
    String longName = "a".repeat(500);
    assertEquals(401, statusOf(() -> service("fixed").login(longName, "x")));
    verify(events).add(eq("LOGIN_FAILURE"), anyString(), argThat(u -> u.length() <= 60), anyString());
  }

  @Test void blankCredentialsAreRejectedNotCrashing() {
    assertEquals(HttpStatus.UNAUTHORIZED.value(), statusOf(() -> service("fixed").login(null, null)));
  }
}
