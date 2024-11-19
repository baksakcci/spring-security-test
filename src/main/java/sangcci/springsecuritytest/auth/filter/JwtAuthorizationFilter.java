package sangcci.springsecuritytest.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import sangcci.springsecuritytest.auth.util.JwtParser;
import sangcci.springsecuritytest.auth.util.JwtValidator;

@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtValidator jwtValidator;
    private final JwtParser jwtParser;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1 - get token from request
        String token = getBearerToken(request);
        // if you do not have a token, pass the filter to register as an anonymous user.
        if (token != null && jwtValidator.validateToken(token)) {
            // 2 - token validate
            jwtValidator.validateToken(token);

            // 3 - token extract to username
            String email = jwtParser.extractUsername(token);

            // 4 - extract user from userDetailsService
            UserDetails userDetails = userDetailsService.loadUserByUsername(email);

            // 5 - generate AuthenticationToken
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.getAuthorities()
            );

            // 6 - add info (default - remote ip address, session id)
            authenticationToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );

            // 7 - save in Security Context Holder
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        }

        // 8 - go next filter
        filterChain.doFilter(request, response);
    }

    private String getBearerToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
