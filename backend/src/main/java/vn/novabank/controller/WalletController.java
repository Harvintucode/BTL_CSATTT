package vn.novabank.controller;
import vn.novabank.service.WalletService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import java.math.BigDecimal;
import java.util.*;
@RestController @RequestMapping("/api")
public class WalletController {
  private final WalletService service;
  public WalletController(WalletService service) { this.service=service; }
  private long userId(Authentication a) { return Long.parseLong(a.getName()); }
  @GetMapping("/wallets") public List<Map<String,Object>> wallets(Authentication a) { return service.wallets(userId(a)); }
  @GetMapping("/wallets/{id}") public Map<String,Object> wallet(@PathVariable long id, Authentication a) { return service.wallet(id,userId(a)); }
  @GetMapping("/transfers") public List<Map<String,Object>> history(Authentication a) { return service.history(userId(a)); }
  @PostMapping("/transfers") public Map<String,Object> transfer(@Valid @RequestBody TransferRequest r, Authentication a) {
    return service.transfer(userId(a),r.destinationAccount(),r.destinationName(),r.amount(),r.note());
  }
  public record TransferRequest(@NotBlank @Size(max=20) String destinationAccount,@NotBlank @Size(max=100) String destinationName,
    @NotNull @DecimalMin("1000.00") @Digits(integer=16,fraction=2) BigDecimal amount,@Size(max=255) String note) {}
}
