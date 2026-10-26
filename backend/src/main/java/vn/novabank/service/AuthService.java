package vn.novabank.service;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import vn.novabank.config.JwtService;
import vn.novabank.config.LabProperties;
import vn.novabank.repository.SecurityEventRepository;
import vn.novabank.repository.UserRepository;

import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuthService {
  static final int MAX_ATTEMPTS = 5;
  static final long LOCK_MILLIS = 60_000L;
  static final long FAILURE_WINDOW_MILLIS = 15 * 60_000L;
  private static final int MAX_TRACKED_USERNAMES = 10_000;
  private static final int MAX_USERNAME_LENGTH = 60; // matches security_events.username / users.username

  private final UserRepository users; private final PasswordEncoder encoder; private final JwtService jwt;
  private final SecurityEventRepository events; private final LabProperties lab;
  /** Hash compared against when the username does not exist, so response time does not reveal valid usernames. */
  private final String dummyHash;

  private record FailureState(int count, long blockedUntil, long lastFailure) {}
  private final Map<String, FailureState> failed = new ConcurrentHashMap<>();

  public AuthService(UserRepository users, PasswordEncoder encoder, JwtService jwt, SecurityEventRepository events, LabProperties lab) {
    this.users = users; this.encoder = encoder; this.jwt = jwt; this.events = events; this.lab = lab;
    this.dummyHash = encoder.encode("not-a-real-password");
  }

  public Map<String, Object> login(String username, String password) {
    String key = normalize(username);
    long now = System.currentTimeMillis();

    if (!lab.vulnerable()) {
      FailureState state = failed.get(key);
      if (state != null && state.blockedUntil() > now) {
        events.add("BRUTE_FORCE_BLOCK", "HIGH", key, "Login blocked after repeated failures");
        throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many failed attempts; retry after the temporary lock expires.");
      }
    }

    var user = users.findByUsername(key);
    // The vulnerable mode intentionally skips the attempt threshold, but passwords are still BCrypt-hashed.
    String hash = user.isPresent() ? (String) user.get().get("password_hash") : dummyHash;
    boolean passwordOk = encoder.matches(password == null ? "" : password, hash);
    boolean valid = user.isPresent() && passwordOk;

    if (!valid) {
      FailureState next = failed.compute(key, (k, cur) -> {
        boolean stale = cur == null || now - cur.lastFailure() > FAILURE_WINDOW_MILLIS
          || (cur.blockedUntil() != 0 && cur.blockedUntil() <= now);
        int count = (stale ? 0 : cur.count()) + 1;
        long lockUntil = (!lab.vulnerable() && count >= MAX_ATTEMPTS) ? now + LOCK_MILLIS : 0L;
        return new FailureState(count, lockUntil, now);
      });
      pruneIfNeeded(now);
      events.add("LOGIN_FAILURE", next.count() > 3 ? "HIGH" : "MEDIUM", key, "Invalid credentials");
      throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
    }

    failed.remove(key);
    var u = user.get();
    return Map.of("token", jwt.create(((Number) u.get("id")).longValue(), (String) u.get("username"), (String) u.get("role")),
      "tokenType", "Bearer", "expiresIn", 1800,
      "user", Map.of("id", u.get("id"), "username", u.get("username"), "role", u.get("role")));
  }

  private static String normalize(String username) {
    String k = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
    return k.length() > MAX_USERNAME_LENGTH ? k.substring(0, MAX_USERNAME_LENGTH) : k;
  }

  /** Keeps the in-memory counter bounded when an attacker sprays random usernames. */
  private void pruneIfNeeded(long now) {
    if (failed.size() <= MAX_TRACKED_USERNAMES) return;
    failed.entrySet().removeIf(e -> e.getValue().blockedUntil() <= now && now - e.getValue().lastFailure() > FAILURE_WINDOW_MILLIS);
  }
}
