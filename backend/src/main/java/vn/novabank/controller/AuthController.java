package vn.novabank.controller;
import vn.novabank.service.AuthService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
@RestController @RequestMapping("/api/auth")
public class AuthController {
  private final AuthService auth;
  public AuthController(AuthService auth) { this.auth=auth; }
  @PostMapping("/login") public Map<String,Object> login(@Valid @RequestBody LoginRequest r) { return auth.login(r.username(),r.password()); }
  public record LoginRequest(@NotBlank @Size(max=60) String username,@NotBlank @Size(max=128) String password) {}
}
