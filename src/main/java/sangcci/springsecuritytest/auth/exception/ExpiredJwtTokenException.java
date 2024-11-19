package sangcci.springsecuritytest.auth.exception;

import sangcci.springsecuritytest.common.exception.CustomException;

public class ExpiredJwtTokenException extends CustomException {

    public ExpiredJwtTokenException() {
        super(JwtErrorCode.EXPIRED_JWT_TOKEN);
    }
}
