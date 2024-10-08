package sangcci.springsecuritytest.auth.dto;

public record LoginRequest(
        String username,
        String password
) {

}
