package sangcci.springsecuritytest.test;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class TestController {

    //@PreAuthorize(value = "Role.ADMIN")
    @GetMapping("/admin")
    public ResponseEntity<String> callAdmin() {
        return ResponseEntity.ok("admin yeah!");
    }

    //@PreAuthorize(value = "Role.USER")
    @GetMapping
    public ResponseEntity<String> callUser() {
        return ResponseEntity.ok("user yeah!");
    }
}
