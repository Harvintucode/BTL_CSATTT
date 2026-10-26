package vn.novabank.repository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import java.util.*;
@Repository
public class UserRepository {
  private final JdbcTemplate db;
  public UserRepository(JdbcTemplate db) { this.db = db; }
  public Optional<Map<String,Object>> findByUsername(String username) {
    return db.query("SELECT id, username, password_hash, role FROM users WHERE username = ?",
      rs -> rs.next() ? Optional.of(Map.of("id",rs.getLong("id"),"username",rs.getString("username"),
      "password_hash",rs.getString("password_hash"),"role",rs.getString("role"))) : Optional.empty(), username);
  }
  public Optional<Map<String,Object>> findById(long id) {
    return db.query("SELECT id, username, role FROM users WHERE id = ?",
      rs -> rs.next() ? Optional.of(Map.of("id",rs.getLong("id"),"username",rs.getString("username"),"role",rs.getString("role"))) : Optional.empty(), id);
  }
}
