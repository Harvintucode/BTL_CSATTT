package vn.novabank.controller;
import vn.novabank.service.LabService;
import org.springframework.web.bind.annotation.*;
import java.util.*;
@RestController @RequestMapping("/api")
public class LabController {
  private final LabService lab;
  public LabController(LabService lab) { this.lab=lab; }
  @GetMapping("/health") public Map<String,Object> health() { return lab.status(); }
  @GetMapping("/lab/scenarios") public List<Map<String,Object>> scenarios() { return lab.scenarios(); }
  @GetMapping("/lab/customer-search") public List<Map<String,Object>> search(@RequestParam(defaultValue="") String q) { return lab.search(q); }
  @GetMapping("/admin/security-events") public List<Map<String,Object>> events() { return lab.events(); }
}
