package sangcci.springsecuritytest.auth.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import sangcci.springsecuritytest.common.exception.code.GlobalErrorCode;
import sangcci.springsecuritytest.common.response.Response;

@Slf4j
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public CustomAuthenticationEntryPoint() {
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException, ServletException {

        log.info(authException.getMessage());

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
