package sangcci.springsecuritytest.user.application;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sangcci.springsecuritytest.user.domain.Member;
import sangcci.springsecuritytest.user.dto.SignupRequest;
import sangcci.springsecuritytest.user.infra.MemberJpaRepository;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberJpaRepository memberJpaRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void create(SignupRequest signupRequest) {
        // 1 - username 중복 체크
        if (memberJpaRepository.existsByUsername(signupRequest.username())) {
            throw new RuntimeException("아이디가 이미 존재합니다.");
        }

        // 2 - password encoding
        String encodedPassword = passwordEncoder.encode(signupRequest.password());

        // 3 - entity 생성
        Member member = signupRequest.toEntity(encodedPassword);

        // 4 - save
        memberJpaRepository.save(member);
    }
}
