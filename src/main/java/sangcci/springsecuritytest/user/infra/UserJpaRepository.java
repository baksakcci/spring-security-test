package sangcci.springsecuritytest.user.infra;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import sangcci.springsecuritytest.user.domain.User;

public interface UserJpaRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
}
