package sangcci.springsecuritytest.auth.request;

public record LoginRequest(
        String username,
        String password
) {

}
