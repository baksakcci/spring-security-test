package sangcci.springsecuritytest.user.exception;

import sangcci.springsecuritytest.common.exception.CustomException;

public class MemberNotFoundException extends CustomException {
    public MemberNotFoundException() {
        super(MemberErrorCode.MEMBER_NOT_FOUND);
    }
}