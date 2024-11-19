package sangcci.springsecuritytest.auth.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import sangcci.springsecuritytest.auth.util.JwtProvider;

@RequiredArgsConstructor
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 인증 성공 - JWT 발급
        String accessToken = jwtProvider.generateAccessToken(authentication.getName());

        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader("Authorization", accessToken);
    }
}
