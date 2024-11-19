package sangcci.springsecuritytest.auth.oauth2;

import java.util.Map;
import lombok.Builder;
import sangcci.springsecuritytest.user.domain.LoginProvider;

@Builder
public record OAuth2UserInfo(
        LoginProvider loginProvider,
        String providerId,
        String nickname,
        String email,
        String profile
) {

    public static OAuth2UserInfo ofGoogle(Map<String, Object> attributes) {
        return OAuth2UserInfo.builder()
                .loginProvider(LoginProvider.GOOGLE)
                .providerId((String) attributes.get("sub"))
                .nickname((String) attributes.get("nickname"))
                .email((String) attributes.get("email"))
                .profile((String) attributes.get("picture"))
                .build();
    }

    public static OAuth2UserInfo ofKakao(Map<String, Object> attributes) {
        Map<String, Object> account = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) account.get("profile");
        Long providerId = (Long) attributes.get("id");

        return OAuth2UserInfo.builder()
                .loginProvider(LoginProvider.KAKAO)
                .providerId(String.valueOf(providerId))
                .nickname((String) profile.get("nickname"))
                .email((String) account.get("email"))
                .build();
    }
}