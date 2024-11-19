package sangcci.springsecuritytest.user.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Embeddable
public class LoginType {

    @Enumerated(EnumType.STRING)
    private LoginProvider loginProvider;

    // OAuth2 Auth Server 별 식별자(OAuth2를 사용하지 않은 로그인일 경우 null)
    @Column(nullable = true)
    private String providerId;

    @Builder
    private LoginType(LoginProvider loginProvider, String providerId) {
        this.loginProvider = loginProvider;
        this.providerId = providerId;
    }
}
