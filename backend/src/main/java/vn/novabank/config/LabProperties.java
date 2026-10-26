package vn.novabank.config;
import org.springframework.boot.context.properties.ConfigurationProperties;
@ConfigurationProperties(prefix="lab")
public record LabProperties(String mode) {
  public boolean vulnerable() { return "vulnerable".equalsIgnoreCase(mode); }
}
