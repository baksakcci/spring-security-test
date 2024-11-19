package sangcci.springsecuritytest.auth.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import sangcci.springsecuritytest.common.exception.CustomException;
import sangcci.springsecuritytest.common.exception.code.ErrorCode;
import sangcci.springsecuritytest.common.response.Response;

@Component
public class JwtExceptionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (InvalidJwtTokenException | ExpiredJwtTokenException | InvalidJwtSignatureException e) {
            setResponse(response, e);
        }
    }

    private void setResponse(HttpServletResponse response, CustomException e) throws RuntimeException, IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        ErrorCode errorCode = e.getErrorCode();

        Response<Void> apiResponse = Response.onFailure(
                errorCode.code(),
                errorCode.message()
        );

        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json");
        response.setStatus(errorCode.status());
        response.getWriter().write(objectMapper.writeValueAsString(apiResponse));
    }
}
