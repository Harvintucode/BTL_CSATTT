package vn.novabank.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Returns every API error as {"status","error","message"} so the frontend can show a meaningful message.
 * Without this, Spring Boot hides ResponseStatusException reasons and the UI only sees a generic failure.
 */
@RestControllerAdvice
public class ApiExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

  @ExceptionHandler(Exception.class)
  public ResponseEntity<Map<String, Object>> handle(Exception e) {
    if (e instanceof MethodArgumentNotValidException m) {
      String msg = m.getBindingResult().getFieldErrors().stream()
        .map(f -> f.getField() + ": " + f.getDefaultMessage())
        .collect(Collectors.joining("; "));
      return body(HttpStatus.BAD_REQUEST, msg.isBlank() ? "Invalid request" : msg);
    }
    if (e instanceof HttpMessageNotReadableException) {
      return body(HttpStatus.BAD_REQUEST, "Malformed or unreadable request body");
    }
    if (e instanceof MethodArgumentTypeMismatchException) {
      return body(HttpStatus.BAD_REQUEST, "Invalid request parameter");
    }
    if (e instanceof ErrorResponse er) { // ResponseStatusException, 404, 405, 415 ...
      String detail = er.getBody().getDetail();
      return body(er.getStatusCode(), detail == null || detail.isBlank() ? "Request failed" : detail);
    }
    log.error("Unhandled error", e);
    return body(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error");
  }

  private static ResponseEntity<Map<String, Object>> body(HttpStatusCode status, String message) {
    Map<String, Object> b = new LinkedHashMap<>();
    b.put("status", status.value());
    HttpStatus known = HttpStatus.resolve(status.value());
    b.put("error", known == null ? "Error" : known.getReasonPhrase());
    b.put("message", message);
    return ResponseEntity.status(status).body(b);
  }
}
