package sangcci.springsecuritytest.auth.exception;

import sangcci.springsecuritytest.common.exception.CustomException;

public class InvalidJwtSignatureException extends CustomException {

    public InvalidJwtSignatureException() {
        super(JwtErrorCode.INVALID_JWT_SIGNATURE);
    }
}
