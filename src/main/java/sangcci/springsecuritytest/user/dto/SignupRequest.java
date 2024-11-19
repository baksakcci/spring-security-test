package sangcci.springsecuritytest.user.dto;

import sangcci.springsecuritytest.user.domain.LoginProvider;
import sangcci.springsecuritytest.user.domain.Member;
import sangcci.springsecuritytest.user.domain.Role;

public record SignupRequest(
        String email,
        String password,
        String nickname
) {

    public Member toEntity(String encodedPassword) {
        return Member.builder()
                .email(email)
                .password(encodedPassword)
                .loginProvider(LoginProvider.ORIGINAL)
                .providerId(null)
                .nickname(nickname)
                .role(Role.USER)
                .build();
    }
}
