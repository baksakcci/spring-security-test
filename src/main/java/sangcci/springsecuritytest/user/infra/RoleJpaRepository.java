package sangcci.springsecuritytest.user.infra;

import org.springframework.data.jpa.repository.JpaRepository;
import sangcci.springsecuritytest.user.domain.Role;

public interface RoleJpaRepository extends JpaRepository<Role, Long> {

}
