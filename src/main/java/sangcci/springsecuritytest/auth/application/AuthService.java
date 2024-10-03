package sangcci.springsecuritytest.auth.application;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sangcci.springsecuritytest.auth.dto.AuthResponse;
import sangcci.springsecuritytest.auth.dto.LoginRequestDto;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;

    private final JwtProvider jwtProvider;

    @Transactional(readOnly = true)
    public AuthResponse login(
            LoginRequestDto loginRequestDto
    ) {
        // 1 - AuthenticationManager 인증
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                loginRequestDto.username(),
                loginRequestDto.password()
        );
        Authentication authenticate = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        // 2 - SecurityContextHolder에 저장 -> 필요 없지 않나?

        // 3 - jwt 발급
        String generatedJwt = jwtProvider.generate(authenticate);

        return AuthResponse.of(generatedJwt);
    }
}
