package sangcci.springsecuritytest.common.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class Response<T> {

    private String code;
    private String message;
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private T result;

    public Response(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public static <T> Response<T> onSuccess(T result) {
        return new Response<>("SUCCESS", "요청에 성공하였습니다.", result);
    }

    public static <T> Response<T> onSuccess() {
        return new Response<>("SUCCESS", "요청에 성공하였습니다.");
    }

    public static <T> Response<T> onFailure(String errorCode, String message) {
        return new Response<>(errorCode, message);
    }
}
