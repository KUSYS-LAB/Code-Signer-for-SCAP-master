package kr.ac.korea.sans.cs.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import kr.ac.korea.sans.cs.constant.Constants;
import kr.ac.korea.sans.cs.response.CsAppResponse;
import kr.ac.korea.sans.cs.response.CsErrorResponse;
import kr.ac.korea.sans.cs.response.CsSecretDto;
import kr.ac.korea.sans.cs.util.CryptoHelper;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;


@Service
public class CsServiceImpl implements CsService {
    private static final Logger logger = LoggerFactory.getLogger(CsServiceImpl.class);

    @Override
    public CsSecretDto decryptService(Map<String, Object> json) throws Exception {
        Map<String, Object> body = (Map<String, Object>) json.get("body");
        String signature = (String)json.get("signature");

        CryptoHelper cryptoHelper = CryptoHelper.getInstance();
        ObjectMapper objectMapper = new ObjectMapper();

        // [1] isSigVal
        String cpk = (String)body.get("cpk");
        PublicKey cpkPublicKey = cryptoHelper.convertStringToPK(cpk);

        byte[] decodedSignature = Base64.decode(signature);

        String bodyString = objectMapper.writeValueAsString(body);
        byte[] baBody = bodyString.getBytes("UTF-8");

        if (!cryptoHelper.verifySignature(cpkPublicKey, decodedSignature, baBody)) {
            throw new CsErrorResponse("Signature Validation ERROR");
        }

        // [2] EPK+CS(SK AS-CS) 복호화

        // [3] isTicketVal
        byte[] ticketData2 = Base64Utils.decodeFromString((String) body.get("ticket"));
        PrivateKey privateKey = cryptoHelper.getPrivate("CS-KeyPair/CS-PrivateKey", Constants.TYPE_PKI);
        String esk = new String(cryptoHelper.decryptWithRsa(
                Base64Utils.decodeFromString((String) body.get("esk")), privateKey));
        Map<String, Object> eskMap = objectMapper.readValue(esk, Map.class);


        String skBase64 = (String) eskMap.get("sk");
        String ivBase64 = (String) eskMap.get("iv");
        SecretKeySpec sk = new SecretKeySpec(Base64Utils.decodeFromString(skBase64), "AES");
        IvParameterSpec iv = new IvParameterSpec(Base64Utils.decodeFromString(ivBase64));
        byte[] decryptedTicket = cryptoHelper.decryptWithAes(sk, iv, ticketData2);
        Map<String, Object> ticket = objectMapper.readValue(decryptedTicket, Map.class);

        Map<String, Object> timeData = (Map<String, Object>) body.get("time");

        if (!cryptoHelper.isTicketVal(ticket, timeData)){
            throw new CsErrorResponse("Ticket Validation ERROR");
        }

        // [4] isAuthVal
//        Map<String, Object> auth = (Map) body.get("auth");
        Map<String, Object> auth = objectMapper.readValue(
                new String(cryptoHelper.decryptWithRsa(
                        Base64Utils.decodeFromString((String) body.get("auth")),
                        privateKey)),
                Map.class);

        // need to fixed, check institute!
        if (!ticket.get("cname").equals(auth.get("cname"))/* || !ticket.get("institute").equals(auth.get("institute"))*/) {
            throw new CsErrorResponse("Auth Validation ERROR");
        }

        return new CsSecretDto(sk, iv, auth);
    }

    @Override
    public CsAppResponse<Map<String, Object>> encryptService(Map<String, Object> body, MultipartFile ac, CsSecretDto csSecretDto) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        CryptoHelper cryptoHelper = CryptoHelper.getInstance();
        CsAppResponse<Map<String, Object>> csAppResponse = new CsAppResponse<>();

        // res body-4. ts
        SimpleDateFormat formatter = new SimpleDateFormat(Constants.CS_DATE_FORMAT);
        String ts = formatter.format(Calendar.getInstance().getTime());

        //res body-1. ticket TGS 발행
        String cname = csSecretDto.getAuth().get("cname").toString();

        Map<String, String> time = new HashMap<>();
        time.put("from", (String) ((Map<String, Object>)body.get("time")).get("from"));
        time.put("to", (String) ((Map<String, Object>)body.get("time")).get("to"));

        Map<String, Object> ticketMap = new HashMap<>();
        ticketMap.put("cname", cname);
        ticketMap.put("ts", time);

        //cData jackson
        String ticketStr = objectMapper.writeValueAsString(ticketMap);

        // sk 비밀키 생성
        SecretKeySpec sk = (SecretKeySpec) cryptoHelper.getSecretEncryptionKey();
        IvParameterSpec iv = cryptoHelper.getIvParameterSpec();

        Map<String, Object> eskMap = new HashMap<>();
        eskMap.put("sk", Base64Utils.encodeToString(sk.getEncoded()));
        eskMap.put("iv", Base64Utils.encodeToString(iv.getIV()));

        //jsonCdata 평문 암호화
        byte[] cipherText = cryptoHelper.encryptWithAes(sk, iv,  ticketStr);

        //암호화한 byte[] type의 데이터를 base64로 변환
        String ticket = Base64Utils.encodeToString(cipherText);

        //res body-2. signature_ac 전자서명
        byte[] encryptedAC = cryptoHelper.signAC(ac.getBytes());
        String signature_ac = Base64Utils.encodeToString(encryptedAC);

        // res body-5. spk - CS의 공개키
//        byte[] spk = cryptoHelper.getPublicKey();
        String spk = Base64Utils.encodeToString(
                cryptoHelper.getPublic("CS-KeyPair/CS-PublicKey",
                        Constants.TYPE_PKI).getEncoded());

        Map<String, Object> responseBodyMap = new HashMap<String, Object>( );
        responseBodyMap.put("ticket", ticket);
        responseBodyMap.put("sig_ac", signature_ac);
        responseBodyMap.put("esk", eskMap);
        responseBodyMap.put("ts" , ts );
        responseBodyMap.put("spk", spk);

        //body jackson
        String responseBodyStr = objectMapper.writeValueAsString(responseBodyMap);

        //res signature - body에 대한 ECDSA & base64 인코딩
        byte[] signature = cryptoHelper.signAC(responseBodyStr.getBytes());
        String signatureBase64 = Base64Utils.encodeToString(signature);

        //response 응답형식
        csAppResponse.setBody(responseBodyMap);
        csAppResponse.setSignature(signatureBase64);

        return csAppResponse;
    }
}
