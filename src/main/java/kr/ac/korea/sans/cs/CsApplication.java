package kr.ac.korea.sans.cs;

import kr.ac.korea.sans.cs.util.CryptoHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.annotation.PostConstruct;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.util.TimeZone;

@SpringBootApplication
public class CsApplication {
    private static final Logger logger = LoggerFactory.getLogger(CsApplication.class);

    @Value("${publickey.type}")
    private String publicKeyType;

    public static void main(String[] args) {
        SpringApplication.run(CsApplication.class, args);
    }

    @PostConstruct
    public void init() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, IOException {
        TimeZone.setDefault(TimeZone.getTimeZone("Asia/Seoul"));
        Security.addProvider(new BouncyCastleProvider());

        CryptoHelper cryptoHelper = CryptoHelper.getInstance();
        if (!new File("CS-KeyPair").exists()) new File("CS-KeyPair").mkdir();
        if (!new File("CS-KeyPair/CS-PublicKey").exists() || !new File("CS-KeyPair/CS-PrivateKey").exists()) {
//            logger.info("create key pair");
//            KeyPair keyPair = cryptoHelper.generateEcKeyPair();
            KeyPair keyPair = null;
            if (publicKeyType.toLowerCase().trim().equals("ec")) keyPair = cryptoHelper.generateEcKeyPair();
            else if (publicKeyType.toLowerCase().trim().equals("rsa")) keyPair = cryptoHelper.generateRsaKeyPair();

            cryptoHelper.writeToFile(new File("CS-KeyPair/CS-PublicKey"), keyPair.getPublic().getEncoded());
            cryptoHelper.writeToFile(new File("CS-KeyPair/CS-PrivateKey"), keyPair.getPrivate().getEncoded());
        }
    }
}