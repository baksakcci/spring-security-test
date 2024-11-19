package sangcci.springsecuritytest.user.exception;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import sangcci.springsecuritytest.common.exception.code.ErrorCode;
import sangcci.springsecuritytest.common.exception.code.ErrorCodeInterface;

@RequiredArgsConstructor
public enum MemberErrorCode implements ErrorCodeInterface {
    MEMBER_NOT_FOUND(HttpStatus.NOT_FOUND.value(), "MEMBER_NOT_FOUND", "존재하지 않는 회원입니다."),
    MEMBER_ALREADY_EXIST(HttpStatus.CONFLICT.value(), "MEMBER_ALREADY_EXIST", "이미 등록된 이메일이 존재합니다.")
    ;

    private final Integer status;
    private final String errorCode;
    private final String message;

    @Override
    public ErrorCode getErrorCode() {
        return ErrorCode.of(status, errorCode, message);
    }
}