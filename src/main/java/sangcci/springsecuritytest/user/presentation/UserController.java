package sangcci.springsecuritytest.user.presentation;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sangcci.springsecuritytest.user.application.UserAppender;
import sangcci.springsecuritytest.user.dto.SignupRequest;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class UserController {

    private final UserAppender userAppender;

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(
            @RequestBody SignupRequest signupRequest
    ) {
        userAppender.create(signupRequest);

        return ResponseEntity.noContent()
                .build();
    }
}
