package sangcci.springsecuritytest.auth.oauth2.response;

import sangcci.springsecuritytest.user.domain.LoginProvider;
import sangcci.springsecuritytest.user.domain.Member;

public record MemberCreateOAuthResponse(
        LoginProvider provider,
        String providerId,
        String email
) {
    public static MemberCreateOAuthResponse from(Member member) {
        return new MemberCreateOAuthResponse(
                member.getLoginType().getLoginProvider(),
                member.getLoginType().getProviderId(),
                member.getEmail()
        );
    }
}
