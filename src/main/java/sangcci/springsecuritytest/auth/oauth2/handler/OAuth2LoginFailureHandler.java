package sangcci.springsecuritytest.auth.oauth2.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import sangcci.springsecuritytest.common.exception.code.GlobalErrorCode;
import sangcci.springsecuritytest.common.response.Response;

@Slf4j
@Component
public class OAuth2LoginFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException, ServletException {
        log.info(exception.getMessage());

        ObjectMapper objectMapper = new ObjectMapper();

        Response<GlobalErrorCode> errorResponse = Response.onFailure(
                GlobalErrorCode.UNAUTHORIZED_ERROR.getErrorCode().code(),
                GlobalErrorCode.UNAUTHORIZED_ERROR.getErrorCode().message()
        );

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
