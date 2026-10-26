package vn.novabank.config;
import org.springframework.boot.CommandLineRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
@Component
public class SeedData implements CommandLineRunner {
  private final JdbcTemplate db; private final PasswordEncoder encoder;
  public SeedData(JdbcTemplate db, PasswordEncoder encoder) { this.db=db; this.encoder=encoder; }
  @Override public void run(String... args) {
    seedUser(1,"huy","123456","CUSTOMER");
    seedUser(2,"bob","123456","CUSTOMER");
    seedUser(3,"admin","admin123","ADMIN");
    db.update("INSERT IGNORE INTO wallets(id,owner_id,account_number,balance) VALUES(1,1,'190000008291',25680000.00),(2,2,'190000009022',12000000.00)");
    db.update("INSERT IGNORE INTO transfers(id,source_wallet_id,destination_account,destination_name,amount,note,status) VALUES(1,1,'190000009022','Bob Nguyen',250000.00,'Giao dịch demo mẫu','SIMULATED'),(2,2, '190000008291','Huy Nguyen',100000.00,'Giao dịch demo mẫu','SIMULATED')");
    seedScenario("RECON_PORT_SCAN","Recon + Port Scan","MEDIUM","V1 exposes unnecessary ports/services","V2 publishes only Nginx; backend and DB stay private");
    seedScenario("EXPOSED_SERVICE","Unnecessary exposed service","HIGH","Database/service is reachable outside app network","Internal Docker network; no published DB/backend ports");
    seedScenario("BRUTE_FORCE","Brute-force Login","HIGH","No attempt threshold in vulnerable mode","Rate limit/temporary block and security event");
    seedScenario("SQL_INJECTION","SQL Injection","CRITICAL","Vulnerable lab path concatenates query input","Prepared statement with bound parameter");
    seedScenario("IDOR","IDOR / Broken Access Control","HIGH","Vulnerable mode reads wallet by ID without ownership","Every wallet lookup binds wallet ID to authenticated owner");
    seedScenario("HTTP_SNIFFING","HTTP Sniffing","MEDIUM","HTTP demo payload is plaintext on isolated localhost","Use HTTPS/TLS for any non-local deployment");
  }
  private void seedUser(long id,String name,String pass,String role) {
    Integer exists = db.queryForObject("SELECT COUNT(*) FROM users WHERE id = ? OR username = ?", Integer.class, id, name);
    if (exists != null && exists > 0) return; // skip the expensive BCrypt hash on restarts
    db.update("INSERT INTO users(id,username,password_hash,role) VALUES(?,?,?,?)",id,name,encoder.encode(pass),role);
  }
  private void seedScenario(String key,String title,String severity,String v1,String v2) {
    db.update("INSERT INTO lab_scenarios(scenario_key,title,severity,vulnerable_behavior,fixed_behavior) VALUES(?,?,?,?,?) "
      + "ON DUPLICATE KEY UPDATE title=VALUES(title),severity=VALUES(severity),vulnerable_behavior=VALUES(vulnerable_behavior),fixed_behavior=VALUES(fixed_behavior)",key,title,severity,v1,v2);
  }
}
