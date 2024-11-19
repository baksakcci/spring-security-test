package sangcci.springsecuritytest.auth.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtProvider {

    private final long accessTokenExpirationDate;

    private final SecretKey secretKey;

    public JwtProvider(
            @Value("${jwt.secret-key}") String secretKey,
            @Value("${jwt.access.expiration}") long accessTokenExpirationDate
    ) {
        this.secretKey = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(secretKey));
        this.accessTokenExpirationDate = accessTokenExpirationDate;
    }

    public String generate(String email) {
        Date currentDate = new Date();
        Date expireDate = new Date(currentDate.getTime() + accessTokenExpirationDate);

        return Jwts.builder()
                .subject(email)
                .issuedAt(currentDate)
                .expiration(expireDate)
                .signWith(secretKey)
                .compact();
    }
}
