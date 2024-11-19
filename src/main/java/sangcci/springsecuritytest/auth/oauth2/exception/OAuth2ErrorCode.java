package sangcci.springsecuritytest.auth.oauth2.exception;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import sangcci.springsecuritytest.common.exception.code.ErrorCode;
import sangcci.springsecuritytest.common.exception.code.ErrorCodeInterface;

@RequiredArgsConstructor
public enum OAuth2ErrorCode implements ErrorCodeInterface {

    UNSUPPORTED_PROVIDER(HttpStatus.BAD_REQUEST.value(), "UNSUPPORTED_PROVIDER", "지원하지 않는 provider 입니다.")
    ;

    private final Integer status;
    private final String errorCode;
    private final String message;

    @Override
    public ErrorCode getErrorCode() {
        return null;
    }
}
