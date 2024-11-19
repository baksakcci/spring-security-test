package sangcci.springsecuritytest.auth.oauth2.exception;

import sangcci.springsecuritytest.common.exception.CustomException;

public class UnsupportedProviderException extends CustomException {
    public UnsupportedProviderException() {
        super(OAuth2ErrorCode.UNSUPPORTED_PROVIDER);
    }
}
