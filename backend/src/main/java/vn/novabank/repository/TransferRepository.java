package vn.novabank.repository;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

@Repository
public class TransferRepository {
  private final JdbcTemplate db;
  public TransferRepository(JdbcTemplate db) { this.db = db; }

  /** Transfers sent by the user (direction OUT) and received by one of the user's wallets (direction IN). */
  public List<Map<String, Object>> history(long ownerId) {
    return db.queryForList(
      "SELECT t.id, t.destination_account, t.destination_name, t.amount, t.note, t.status, t.created_at, "
        + "CASE WHEN w.owner_id = ? THEN 'OUT' ELSE 'IN' END AS direction, su.username AS source_username "
        + "FROM transfers t JOIN wallets w ON w.id = t.source_wallet_id JOIN users su ON su.id = w.owner_id "
        + "WHERE w.owner_id = ? OR t.destination_account IN (SELECT account_number FROM wallets WHERE owner_id = ?) "
        + "ORDER BY t.id DESC LIMIT 100", ownerId, ownerId, ownerId);
  }

  public long create(long sourceWalletId, String destinationAccount, String destinationName, BigDecimal amount, String note) {
    KeyHolder keys = new GeneratedKeyHolder();
    db.update(con -> {
      PreparedStatement ps = con.prepareStatement(
        "INSERT INTO transfers(source_wallet_id,destination_account,destination_name,amount,note,status) VALUES(?,?,?,?,?,'SIMULATED')",
        Statement.RETURN_GENERATED_KEYS);
      ps.setLong(1, sourceWalletId);
      ps.setString(2, destinationAccount);
      ps.setString(3, destinationName);
      ps.setBigDecimal(4, amount);
      ps.setString(5, note);
      return ps;
    }, keys);
    Number key = keys.getKey();
    if (key == null) throw new IllegalStateException("No generated key returned for transfer");
    return key.longValue();
  }
}
