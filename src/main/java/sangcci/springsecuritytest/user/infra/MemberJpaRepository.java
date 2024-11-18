package sangcci.springsecuritytest.user.infra;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import sangcci.springsecuritytest.user.domain.Member;

public interface MemberJpaRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByUsername(String username);

    boolean existsByUsername(String username);

    Optional<Member> findByEmail(String email);
}
