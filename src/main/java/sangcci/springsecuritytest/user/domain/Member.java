package sangcci.springsecuritytest.user.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "members")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true)
    private String email;
    @Column(nullable = true)
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;
    @Embedded
    private LoginType loginType;
    private String nickname;

    @Builder
    private Member(
            String email,
            String password,
            LoginProvider loginProvider,
            String providerId,
            String nickname,
            Role role
    ) {
        this.email = email;
        this.password = password;
        this.role = role;
        this.loginType = LoginType.builder()
                .loginProvider(loginProvider)
                .providerId(providerId)
                .build();
        this.nickname = nickname;
    }

    /**
     * 임시 GUEST 생성 메서드
     *
     * 아직 회원가입이 완전히 이루어진 상태가 아니기 때문에 GUEST 권한으로 등록되어 있습니다.
     * 회원가입에 필요한 정보들을 모두 기입할 시 USER 권한으로 승격됩니다.
     * - password 없음
     */
    public static Member createTemporary(
            String email,
            String nickname,
            LoginProvider loginProvider,
            String providerId
    ) {
        return Member.builder()
                .email(email)
                .nickname(nickname)
                .loginProvider(loginProvider)
                .providerId(providerId)
                .role(Role.GUEST)
                .build();
    }
}
