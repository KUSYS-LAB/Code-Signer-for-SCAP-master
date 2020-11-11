package kr.ac.korea.sans.cs.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class CsSecretDto {
    private SecretKeySpec sk;
    private IvParameterSpec iv;
    private Map<String, Object> auth;
}
