package sangcci.springsecuritytest.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.MessageFormat;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import sangcci.springsecuritytest.auth.dto.LoginRequest;

@Component
public class JwtAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final AntPathRequestMatcher PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/api/auth/login", "POST");

    private final ObjectMapper objectMapper;

    public JwtAuthenticationFilter() {
        super(PATH_REQUEST_MATCHER);
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        // 1 - contentType 체크
        validateContentType(request);

        // 2 - Json to String parsing
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);

        // 3 - usernamePasswordAuthenticationToken 생성
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                loginRequest.username(),
                loginRequest.password()
        );

        // 4 - authenticationManager 인증 후 반환
        return this.getAuthenticationManager().authenticate(usernamePasswordAuthenticationToken);
    }

    private void validateContentType(HttpServletRequest request) {
        String contentType = request.getContentType();

        if (contentType == null || contentType.equals("application/json")) {
            throw new AuthenticationServiceException(
                    MessageFormat.format("ContentType이 {}가 아닙니다", request.getContentType()));
        }
    }
}
