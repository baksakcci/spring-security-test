package sangcci.springsecuritytest.user.dto;

import sangcci.springsecuritytest.user.domain.Member;

public record SignupRequest(
        String username,
        String password,
        String email,
        String nickname
) {

    public Member toEntity(String encodedPassword) {
        return Member.builder()
                .username(username)
                .password(encodedPassword)
                .email(email)
                .nickname(nickname)
                .build();
    }
}
