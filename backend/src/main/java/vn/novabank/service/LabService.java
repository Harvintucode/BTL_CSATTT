package vn.novabank.service;
import vn.novabank.config.LabProperties;
import vn.novabank.repository.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.util.*;
@Service
public class LabService {
  private final JdbcTemplate db; private final LabProperties lab; private final SecurityEventRepository events;
  public LabService(JdbcTemplate db, LabProperties lab, SecurityEventRepository events) { this.db=db; this.lab=lab; this.events=events; }
  public List<Map<String,Object>> scenarios() { return db.queryForList("SELECT scenario_key,title,severity,vulnerable_behavior,fixed_behavior FROM lab_scenarios ORDER BY scenario_key"); }
  public List<Map<String,Object>> search(String q) {
    String value = q == null ? "" : q;
    if(value.length()>80) throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.BAD_REQUEST,"Search term too long");
    if(lab.vulnerable()) {
      events.add("SQLI_PATTERN_TEST","HIGH","anonymous","Vulnerable lab search path invoked");
      // Intentionally unsafe for isolated lab demonstration only.
      return db.queryForList("SELECT id,username,role FROM users WHERE username LIKE '%" + value + "%'");
    }
    return db.queryForList("SELECT id,username,role FROM users WHERE username LIKE ?", "%"+value+"%");
  }
  public List<Map<String,Object>> events() { return events.latest(); }
  public Map<String,Object> status() { return Map.of("service","NovaBank Mini Cyber Range","status","UP","mode",lab.vulnerable()?"VULNERABLE":"FIXED","scope","localhost-only"); }
}
