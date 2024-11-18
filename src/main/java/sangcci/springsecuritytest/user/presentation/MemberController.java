package sangcci.springsecuritytest.user.presentation;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import sangcci.springsecuritytest.user.application.MemberService;
import sangcci.springsecuritytest.user.dto.SignupRequest;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(
            @RequestBody SignupRequest signupRequest
    ) {
        memberService.create(signupRequest);

        return ResponseEntity.noContent()
                .build();
    }
}
