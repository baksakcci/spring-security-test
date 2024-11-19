package sangcci.springsecuritytest.auth.util;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import sangcci.springsecuritytest.auth.exception.ExpiredJwtTokenException;
import sangcci.springsecuritytest.auth.exception.InvalidJwtSignatureException;
import sangcci.springsecuritytest.auth.exception.InvalidJwtTokenException;

@Slf4j
@Component
public class JwtValidator {

    private final SecretKey secretKey;

    public JwtValidator(@Value("${jwt.secret-key}") String secretKey) {
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
    }

    public void validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parse(token);
        } catch (MalformedJwtException e) {
            throw new InvalidJwtTokenException();
        } catch (SignatureException e) {
            throw new InvalidJwtSignatureException();
        } catch (ExpiredJwtException e) {
            throw new ExpiredJwtTokenException();
        }
    }

    // TODO: refresh Token 검증 (redis 활용)
}
