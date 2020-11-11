package kr.ac.korea.sans.cs.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.ac.korea.sans.cs.constant.Constants;
import kr.ac.korea.sans.cs.response.CsAppResponse;
import kr.ac.korea.sans.cs.response.CsSecretDto;
import kr.ac.korea.sans.cs.service.CsServiceImpl;
import kr.ac.korea.sans.cs.util.CryptoHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Base64Utils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;


@CrossOrigin("*")
@RestController
public class CsAppController {
    private static final Logger logger = LoggerFactory.getLogger(CsAppController.class);

    @Autowired
    private CsServiceImpl csService;

    @Autowired
    private CryptoHelper cryptoHelper;

    @RequestMapping(value="/hello", method= RequestMethod.GET)
    public String test (HttpServletRequest request) throws Exception {
        return "Hello";
    }


    @RequestMapping(value="/get-sign", method=RequestMethod.POST, consumes = "multipart/form-data")
    public CsAppResponse<Map<String, Object>> getSign(@RequestPart("data") Map<String, Object> json, @RequestPart("ac") MultipartFile ac) throws Exception {
        Map<String, Object> body = (Map<String, Object>) json.get("body");

        CsSecretDto csSecretDto = csService.decryptService(json);
        return csService.encryptService(body, ac, csSecretDto);
    }

    @RequestMapping(value="/get-cert", method=RequestMethod.GET)
    public CsAppResponse<Map<String, Object>> getCertificate() throws Exception {
        PublicKey publicKey = this.cryptoHelper.getPublic("CS-KeyPair/CS-PublicKey", Constants.TYPE_PKI);
        Map<String, Object> body = new HashMap<>();
        ObjectMapper objectMapper = new ObjectMapper();

        body.put("certificate", Base64Utils.encodeToString(publicKey.getEncoded()));
        String bodyStr = objectMapper.writeValueAsString(body);
        logger.info(publicKey.toString());
        logger.info(bodyStr);
        byte[] signature = this.cryptoHelper.signAC(bodyStr.getBytes());

        return new CsAppResponse<>(body, Base64Utils.encodeToString(signature));
    }

}
