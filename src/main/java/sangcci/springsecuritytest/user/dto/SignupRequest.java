package sangcci.springsecuritytest.user.dto;

import sangcci.springsecuritytest.user.domain.User;

public record SignupRequest(
        String username,
        String password,
        String email,
        String nickname
) {

    public User toEntity(String encodedPassword) {
        return User.builder()
                .username(username)
                .password(encodedPassword)
                .email(email)
                .nickname(nickname)
                .build();
    }
}
