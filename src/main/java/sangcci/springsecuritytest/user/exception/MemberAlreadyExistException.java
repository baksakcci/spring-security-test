package sangcci.springsecuritytest.user.exception;

import sangcci.springsecuritytest.common.exception.CustomException;

public class MemberAlreadyExistException extends CustomException {
    public MemberAlreadyExistException() {
        super(MemberErrorCode.MEMBER_ALREADY_EXIST);
    }
}
