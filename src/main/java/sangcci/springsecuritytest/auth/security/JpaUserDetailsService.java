package sangcci.springsecuritytest.auth.security;

import java.util.HashSet;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import sangcci.springsecuritytest.user.domain.User;
import sangcci.springsecuritytest.user.infra.UserJpaRepository;

@Component
@RequiredArgsConstructor
public class JpaUserDetailsService implements UserDetailsService {

    private final UserJpaRepository userJpaRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userJpaRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));

        return new org.springframework.security.core.userdetails.User(
                username,
                user.getPassword(),
                new HashSet<SimpleGrantedAuthority>()
        );
    }
}
