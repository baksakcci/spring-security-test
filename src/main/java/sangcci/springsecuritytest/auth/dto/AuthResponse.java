package sangcci.springsecuritytest.auth.dto;

public record AuthResponse(
        String accessToken
) {

    public static AuthResponse of(final String accessToken) {
        return new AuthResponse(accessToken);
    }
}
