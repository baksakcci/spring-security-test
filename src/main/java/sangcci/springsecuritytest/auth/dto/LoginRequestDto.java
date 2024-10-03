package sangcci.springsecuritytest.auth.dto;

public record LoginRequestDto(
        String username,
        String password
) {

}
