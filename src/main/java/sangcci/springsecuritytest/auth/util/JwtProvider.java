package sangcci.springsecuritytest.auth.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@Getter
public class JwtProvider {

    private final long ACCESS_TIME;
    private final long REFRESH_TIME;

    private final SecretKey secretKey;

    public JwtProvider(
            @Value("${jwt.secret-key}") String secretKey,
            @Value("${jwt.access.expiration}") long ACCESS_TIME,
            @Value("${jwt.refresh.expiration}") long REFRESH_TIME) {
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
        this.ACCESS_TIME = ACCESS_TIME;
        this.REFRESH_TIME = REFRESH_TIME;
    }

    public String generateAccessToken(String email) {
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + ACCESS_TIME);

        return Jwts.builder()
                .subject(email)
                .issuedAt(currentDate)
                .expiration(expireDate)
                .signWith(secretKey)
                .compact();
    }

    public String generateRefreshToken(String email) {
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + REFRESH_TIME);

        return Jwts.builder()
                .subject(email)
                .issuedAt(currentDate)
                .expiration(expireDate)
                .signWith(secretKey)
                .compact();
    }
}
