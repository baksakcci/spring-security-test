package sangcci.springsecuritytest.user.application;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sangcci.springsecuritytest.user.domain.User;
import sangcci.springsecuritytest.user.dto.SignupRequest;
import sangcci.springsecuritytest.user.infra.UserJpaRepository;

@Service
@RequiredArgsConstructor
public class UserAppender {

    private final UserJpaRepository userJpaRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void create(SignupRequest signupRequest) {
        // 1 - username 중복 체크
        if (userJpaRepository.existsByUsername(signupRequest.username())) {
            throw new RuntimeException("아이디가 이미 존재합니다.");
        }

        // 2 - password encoding
        String encodedPassword = passwordEncoder.encode(signupRequest.password());

        // 3 - entity 생성
        User user = signupRequest.toEntity(encodedPassword);

        // 4 - save
        userJpaRepository.save(user);
    }
}
