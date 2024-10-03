package sangcci.springsecuritytest.auth.presentation;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sangcci.springsecuritytest.auth.application.AuthService;
import sangcci.springsecuritytest.auth.dto.AuthResponse;
import sangcci.springsecuritytest.auth.dto.LoginRequestDto;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @RequestBody LoginRequestDto loginRequestDto
    ) {
        return ResponseEntity.ok(authService.login(loginRequestDto));
    }
}
