package kr.ac.korea.sans.cs.constant;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class Constants {
    public static final String CS_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";

    public static String TYPE_PKI;

    @Value("${publickey.type}")
    public void setTypePki(String type) {TYPE_PKI = type;}
}
