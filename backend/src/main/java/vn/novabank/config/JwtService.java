package vn.novabank.config;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
@Component
public class JwtService {
  private final SecretKey key;
  public JwtService(@Value("${app.jwt.secret}") String secret) {
    if (secret.getBytes(StandardCharsets.UTF_8).length < 32) throw new IllegalArgumentException("APP_JWT_SECRET must be at least 32 bytes");
    key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
  }
  public String create(long id, String username, String role) {
    long now = System.currentTimeMillis();
    return Jwts.builder().subject(Long.toString(id)).claim("username", username).claim("role", role)
      .issuedAt(new Date(now)).expiration(new Date(now + 30 * 60 * 1000L)).signWith(key).compact();
  }
  public io.jsonwebtoken.Claims parse(String token) {
    return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
  }
}
