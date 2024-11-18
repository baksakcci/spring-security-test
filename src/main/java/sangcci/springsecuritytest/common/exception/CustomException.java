package sangcci.springsecuritytest.common.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import sangcci.springsecuritytest.common.exception.code.ErrorCode;
import sangcci.springsecuritytest.common.exception.code.ErrorCodeInterface;

@Getter
@RequiredArgsConstructor
public class CustomException extends RuntimeException {
    private final ErrorCodeInterface errorCode;

    public ErrorCode getErrorCode() {
        return this.errorCode.getErrorCode();
    }
}
