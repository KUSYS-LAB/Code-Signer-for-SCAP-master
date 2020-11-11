package kr.ac.korea.sans.cs.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.lang.NonNull;

import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class CsAppResponse<T> {
//    @NonNull
//    private Map<String, Object> body;
    private T body;
    private String signature;
}
