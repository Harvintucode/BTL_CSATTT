package vn.novabank;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
@SpringBootApplication
@ConfigurationPropertiesScan
public class NovaBankApplication {
  public static void main(String[] args) { SpringApplication.run(NovaBankApplication.class, args); }
}
