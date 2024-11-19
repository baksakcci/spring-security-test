package sangcci.springsecuritytest.auth.application;

import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import sangcci.springsecuritytest.user.domain.Member;
import sangcci.springsecuritytest.user.exception.MemberNotFoundException;
import sangcci.springsecuritytest.user.infra.MemberJpaRepository;

@Component
@RequiredArgsConstructor
public class JpaUserDetailsService implements UserDetailsService {

    private final MemberJpaRepository memberJpaRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Member member = memberJpaRepository.findByEmail(email)
                .orElseThrow(MemberNotFoundException::new);

        return new User(
                member.getEmail(),
                member.getPassword(),
                Collections.singleton(new SimpleGrantedAuthority(member.getRole().getText()))
        );
    }
}
