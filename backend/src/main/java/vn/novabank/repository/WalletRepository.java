package vn.novabank.repository;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import java.util.*;
@Repository
public class WalletRepository {
  private final JdbcTemplate db;
  public WalletRepository(JdbcTemplate db) { this.db=db; }
  public List<Map<String,Object>> findForOwner(long ownerId) {
    return db.queryForList("SELECT id, account_number, balance FROM wallets WHERE owner_id = ? ORDER BY id", ownerId);
  }
  public Optional<Map<String,Object>> findByIdAndOwner(long walletId, long ownerId) {
    return db.query("SELECT id, owner_id, account_number, balance FROM wallets WHERE id = ? AND owner_id = ?",
      rs -> rs.next() ? Optional.of(Map.of("id",rs.getLong("id"),"owner_id",rs.getLong("owner_id"),
      "account_number",rs.getString("account_number"),"balance",rs.getBigDecimal("balance"))) : Optional.empty(), walletId, ownerId);
  }
  public Optional<Map<String,Object>> vulnerableFindById(long walletId) {
    return db.query("SELECT id, owner_id, account_number, balance FROM wallets WHERE id = ?",
      rs -> rs.next() ? Optional.of(Map.of("id",rs.getLong("id"),"owner_id",rs.getLong("owner_id"),
      "account_number",rs.getString("account_number"),"balance",rs.getBigDecimal("balance"))) : Optional.empty(), walletId);
  }
}
