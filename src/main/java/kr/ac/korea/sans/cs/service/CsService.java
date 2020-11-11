package kr.ac.korea.sans.cs.service;

import kr.ac.korea.sans.cs.response.CsAppResponse;
import kr.ac.korea.sans.cs.response.CsSecretDto;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

public interface CsService {
    CsSecretDto decryptService(Map<String, Object> json) throws Exception;
    CsAppResponse encryptService(Map<String, Object> body, MultipartFile ac, CsSecretDto csSecretDto) throws Exception;
}
