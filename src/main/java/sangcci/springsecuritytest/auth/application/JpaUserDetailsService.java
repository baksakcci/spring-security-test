package sangcci.springsecuritytest.auth.application;

import java.util.HashSet;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import sangcci.springsecuritytest.user.domain.Member;
import sangcci.springsecuritytest.user.infra.MemberJpaRepository;

@Component
@RequiredArgsConstructor
public class JpaUserDetailsService implements UserDetailsService {

    private final MemberJpaRepository memberJpaRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberJpaRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));

        return new org.springframework.security.core.userdetails.User(
                username,
                member.getPassword(),
                new HashSet<SimpleGrantedAuthority>()
        );
    }
}
