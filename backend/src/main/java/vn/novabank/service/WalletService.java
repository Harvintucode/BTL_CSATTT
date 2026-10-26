package vn.novabank.service;
import vn.novabank.config.LabProperties;
import vn.novabank.repository.*;
import org.springframework.stereotype.Service;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import java.math.BigDecimal;
import java.util.*;
@Service
public class WalletService {
  private final WalletRepository wallets; private final TransferRepository transfers; private final SecurityEventRepository events; private final LabProperties lab;
  public WalletService(WalletRepository wallets, TransferRepository transfers, SecurityEventRepository events, LabProperties lab) {
    this.wallets=wallets; this.transfers=transfers; this.events=events; this.lab=lab;
  }
  public List<Map<String,Object>> wallets(long userId) { return wallets.findForOwner(userId); }
  public Map<String,Object> wallet(long walletId,long userId) {
    var found = lab.vulnerable() ? wallets.vulnerableFindById(walletId) : wallets.findByIdAndOwner(walletId,userId);
    if(found.isEmpty()) { events.add("ACCESS_VIOLATION","HIGH",Long.toString(userId),"Wallet access denied"); throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Wallet not found or access denied"); }
    if(lab.vulnerable() && ((Number)found.get().get("owner_id")).longValue()!=userId)
      events.add("IDOR_CROSS_USER_READ","HIGH",Long.toString(userId),"Vulnerable lab mode: cross-user wallet read");
    return found.get();
  }
  public List<Map<String,Object>> history(long userId) { return transfers.history(userId); }
  public Map<String,Object> transfer(long userId, String destinationAccount, String destinationName, BigDecimal amount, String note) {
    if(amount == null || amount.compareTo(BigDecimal.valueOf(1000)) < 0 || amount.stripTrailingZeros().scale() > 2)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Amount must be at least 1000 VND with at most 2 decimals");
    String account = destinationAccount == null ? "" : destinationAccount.trim();
    String name = destinationName == null ? "" : destinationName.trim();
    if(!account.matches("\\d{6,20}") || name.isEmpty() || name.length() > 100)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid destination details");
    String memo = note == null ? "" : note.trim();
    if(memo.length() > 255) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Note is too long");
    var source = wallets.findForOwner(userId).stream().findFirst().orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,"Wallet not found"));
    if(account.equals(String.valueOf(source.get("account_number"))))
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Cannot transfer to your own account");
    if(amount.compareTo(new BigDecimal(String.valueOf(source.get("balance")))) > 0)
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Insufficient balance");
    // Explicitly a ledger/demo record only. No real balance is debited.
    long id=transfers.create(((Number)source.get("id")).longValue(),account,name,amount,memo);
    return Map.of("id",id,"status","SIMULATED","message","Lab only: no real money or wallet balance changed.");
  }
}
