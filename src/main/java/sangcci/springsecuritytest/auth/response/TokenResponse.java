package sangcci.springsecuritytest.auth.response;

public record TokenResponse(
        String accessToken
) {

    public static TokenResponse of(final String accessToken) {
        return new TokenResponse(accessToken);
    }
}
