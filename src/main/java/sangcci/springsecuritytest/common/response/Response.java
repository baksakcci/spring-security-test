package sangcci.springsecuritytest.common.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public class Response {

    private HttpStatus code;
    private String msg;

    public static Response error(HttpStatus code, String msg) {
        return new Response(code, msg);
    }
}
