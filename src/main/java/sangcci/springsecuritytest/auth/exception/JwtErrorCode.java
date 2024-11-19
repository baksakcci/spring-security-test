package sangcci.springsecuritytest.auth.exception;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import sangcci.springsecuritytest.common.exception.code.ErrorCode;
import sangcci.springsecuritytest.common.exception.code.ErrorCodeInterface;

@RequiredArgsConstructor
public enum JwtErrorCode implements ErrorCodeInterface {

    INVALID_JWT_TOKEN(HttpStatus.BAD_REQUEST.value(), "INVALID_JWT_TOKEN", "유효하지 않은 토큰입니다."),
    INVALID_JWT_SIGNATURE(HttpStatus.BAD_REQUEST.value(), "INVALID_JWT_SIGNATURE", "유효하지 않은 서명입니다."),
    EXPIRED_JWT_TOKEN(HttpStatus.BAD_REQUEST.value(), "EXPIRED_JWT_TOKEN", "토큰이 만료되었습니다.")
    ;

    private final Integer status;
    private final String errorCode;
    private final String message;

    @Override
    public ErrorCode getErrorCode() {
        return ErrorCode.of(status, errorCode, message);
    }
}
