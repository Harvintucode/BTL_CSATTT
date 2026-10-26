package vn.novabank.repository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import java.util.*;
@Repository
public class SecurityEventRepository {
  private final JdbcTemplate db;
  public SecurityEventRepository(JdbcTemplate db) { this.db=db; }
  public void add(String type, String severity, String username, String details) {
    db.update("INSERT INTO security_events(event_type,severity,username,details) VALUES(?,?,?,?)",type,severity,username,details);
  }
  public List<Map<String,Object>> latest() { return db.queryForList("SELECT id,event_type,severity,username,details,created_at FROM security_events ORDER BY id DESC LIMIT 100"); }
}
