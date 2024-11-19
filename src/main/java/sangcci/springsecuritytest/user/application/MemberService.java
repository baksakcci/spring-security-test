package sangcci.springsecuritytest.user.application;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sangcci.springsecuritytest.user.domain.Member;
import sangcci.springsecuritytest.user.dto.SignupRequest;
import sangcci.springsecuritytest.user.exception.MemberAlreadyExistException;
import sangcci.springsecuritytest.user.infra.MemberJpaRepository;

@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberJpaRepository memberJpaRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void create(SignupRequest signupRequest) {
        // 1 - username 중복 체크
        Optional<Member> optionalMember = memberJpaRepository.findByEmail(signupRequest.email());
        if (optionalMember.isPresent()) {
            throw new MemberAlreadyExistException();
        }

        // 2 - password encoding
        String encodedPassword = passwordEncoder.encode(signupRequest.password());

        // 3 - entity 생성
        Member member = signupRequest.toEntity(encodedPassword);

        // 4 - save
        memberJpaRepository.save(member);
    }
}
