package vn.novabank;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import vn.novabank.config.LabProperties;
import vn.novabank.repository.SecurityEventRepository;
import vn.novabank.repository.TransferRepository;
import vn.novabank.repository.WalletRepository;
import vn.novabank.service.WalletService;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class WalletServiceTest {
  private WalletRepository wallets;
  private TransferRepository transfers;
  private SecurityEventRepository events;

  private static final Map<String, Object> HUY_WALLET = Map.of("id", 1L, "owner_id", 1L, "account_number", "190000008291", "balance", new BigDecimal("25680000.00"));
  private static final Map<String, Object> BOB_WALLET = Map.of("id", 2L, "owner_id", 2L, "account_number", "190000009022", "balance", new BigDecimal("12000000.00"));

  @BeforeEach void setUp() {
    wallets = mock(WalletRepository.class);
    transfers = mock(TransferRepository.class);
    events = mock(SecurityEventRepository.class);
    when(wallets.findForOwner(1L)).thenReturn(List.of(HUY_WALLET));
    when(wallets.findByIdAndOwner(2L, 1L)).thenReturn(Optional.empty());
    when(wallets.findByIdAndOwner(1L, 1L)).thenReturn(Optional.of(HUY_WALLET));
    when(wallets.vulnerableFindById(2L)).thenReturn(Optional.of(BOB_WALLET));
    when(transfers.create(anyLong(), anyString(), anyString(), any(), anyString())).thenReturn(42L);
  }

  private WalletService service(String mode) { return new WalletService(wallets, transfers, events, new LabProperties(mode)); }

  private static int statusOf(Runnable r) {
    try { r.run(); return 200; } catch (ResponseStatusException e) { return e.getStatusCode().value(); }
  }

  @Test void fixedModeDeniesOtherUsersWalletAndLogsViolation() {
    assertEquals(403, statusOf(() -> service("fixed").wallet(2L, 1L)));
    verify(events).add(eq("ACCESS_VIOLATION"), anyString(), eq("1"), anyString());
    verify(wallets, never()).vulnerableFindById(anyLong());
  }

  @Test void fixedModeAllowsOwnWallet() {
    assertEquals("190000008291", service("fixed").wallet(1L, 1L).get("account_number"));
  }

  @Test void vulnerableModeLeaksOtherUsersWalletAndLogsIdor() {
    assertEquals("190000009022", service("vulnerable").wallet(2L, 1L).get("account_number"));
    verify(events).add(eq("IDOR_CROSS_USER_READ"), anyString(), eq("1"), anyString());
  }

  @Test void validTransferIsRecordedAsSimulated() {
    var r = service("fixed").transfer(1L, "190000009022", "Bob Nguyen", new BigDecimal("250000"), "demo");
    assertEquals(42L, r.get("id"));
    assertEquals("SIMULATED", r.get("status"));
  }

  @Test void invalidTransfersAreRejectedWith400() {
    WalletService s = service("fixed");
    assertEquals(400, statusOf(() -> s.transfer(1L, "190000009022", "Bob", new BigDecimal("999"), "")));
    assertEquals(400, statusOf(() -> s.transfer(1L, "190000009022", "Bob", new BigDecimal("1000.123"), "")));
    assertEquals(400, statusOf(() -> s.transfer(1L, "190000009022", "Bob", null, "")));
    assertEquals(400, statusOf(() -> s.transfer(1L, "abc", "Bob", new BigDecimal("5000"), "")));
    assertEquals(400, statusOf(() -> s.transfer(1L, "190000009022", "  ", new BigDecimal("5000"), "")));
    assertEquals(400, statusOf(() -> s.transfer(1L, "190000009022", "x".repeat(101), new BigDecimal("5000"), "")));
    assertEquals(400, statusOf(() -> s.transfer(1L, "190000008291", "Huy", new BigDecimal("5000"), "")), "own account");
    assertEquals(400, statusOf(() -> s.transfer(1L, "190000009022", "Bob", new BigDecimal("99999999999"), "")), "insufficient balance");
    verify(transfers, never()).create(anyLong(), anyString(), anyString(), any(), anyString());
  }

  @Test void userWithoutWalletGets404() {
    assertEquals(404, statusOf(() -> service("fixed").transfer(3L, "190000009022", "Bob", new BigDecimal("5000"), "")));
  }
}
