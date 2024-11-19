package sangcci.springsecuritytest.auth.exception;

import sangcci.springsecuritytest.common.exception.CustomException;

public class InvalidJwtTokenException extends CustomException {

    public InvalidJwtTokenException() {
        super(JwtErrorCode.INVALID_JWT_TOKEN);
    }
}
