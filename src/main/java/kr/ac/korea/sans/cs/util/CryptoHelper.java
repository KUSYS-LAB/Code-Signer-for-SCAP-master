package kr.ac.korea.sans.cs.util;

import kr.ac.korea.sans.cs.constant.Constants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.validation.constraints.NotNull;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;

@Component
public class CryptoHelper {

    private static Logger logger = LoggerFactory.getLogger(CryptoHelper.class);

    private static final  CryptoHelper cryptoHelper = new CryptoHelper();

    public CryptoHelper() {

    }

    public static CryptoHelper getInstance() {
        return cryptoHelper;
    }

    public KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        return keyPair;
    }

    public KeyPair generateEcKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
//    	ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
//        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA");
        keyPairGenerator.initialize(ecSpec, random);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public void writeToFile(File output, byte[] toWrite)
        throws IllegalBlockSizeException, BadPaddingException, IOException {
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(toWrite);
        fos.flush();
        fos.close();
    }

    public PrivateKey getPrivate(String filename, String cryptoType) throws Exception {
        // cryptoType {RSA, EC}
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(cryptoType);
        return kf.generatePrivate(spec);
    }

    public PublicKey getPublic(String filename, String cryptoType) throws Exception {
        // cryptoType {RSA, EC}
        byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(cryptoType);
        return kf.generatePublic(spec);
    }

    public static byte[] getSignature(PrivateKey privateKey, byte[] ac) throws GeneralSecurityException {
        Signature signature = null;
        if (Constants.TYPE_PKI.toLowerCase().trim().equals("ec")) {
            signature = Signature.getInstance("SHA256withECDSA");
        } else if (Constants.TYPE_PKI.toLowerCase().trim().equals("rsa")) {
            signature = Signature.getInstance("SHA256withRSA");
        }

        signature.initSign(privateKey);
        signature.update(ac);

        byte[] signatureData = signature.sign();
        return signatureData;
    }

    public static boolean verifySignature(PublicKey publicKey, byte[] signatureData,
                                          byte[] plainData) throws GeneralSecurityException {
        Signature signature = null;
        if (Constants.TYPE_PKI.toLowerCase().trim().equals("ec")) {
            signature = Signature.getInstance("SHA256withECDSA");
        } else if (Constants.TYPE_PKI.toLowerCase().trim().equals("rsa")) {
            signature = Signature.getInstance("SHA256withRSA");
        }

        signature.initVerify(publicKey);
        signature.update(plainData);
        return signature.verify(signatureData);
    }

    public static boolean isTicketVal(Map<String, Object>ticket, Map<String, Object>time) throws ParseException {
        // (1) 티켓의 timestamp와 time의 from/to 비교
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        SimpleDateFormat sdf2 = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        sdf2.setTimeZone(TimeZone.getTimeZone("Asia/Seoul"));
        Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("Asia/Seoul"));
        Date ticketTime = calendar.getTime();


        Date timeFrom = sdf2.parse((String)time.get("from"));
        Date timeTo = sdf2.parse((String)time.get("to"));

        if (ticketTime.after(timeFrom) && ticketTime.before(timeTo)){
            return true;
        }
        return false;
    }

    public PublicKey convertStringToPK(String cpk) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // CPK의 불필요한 구문 삭제
        cpk = cpk.replaceAll("-----BEGIN PUBLIC KEY-----","");
        cpk = cpk.replaceAll("-----END PUBLIC KEY-----","");
        cpk = cpk.replaceAll(System.getProperty("line.separator"),"");

        // CPK Base64 Decode
        byte[] decodedCpk = org.bouncycastle.util.encoders.Base64.decode(cpk);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedCpk);
        KeyFactory kf = KeyFactory.getInstance(Constants.TYPE_PKI);
        PublicKey cpkPublicKey = kf.generatePublic(spec);

        return cpkPublicKey;
    }

    // (1) Generate AC Signature using CS's ECDSA private key
    public byte[] signAC(@NotNull byte[] ac) throws Exception{
        // String cryptoType = GlobalConfig.getInstance().getCertConfig().getCryptoType();
        PrivateKey privateKey = this.getPrivate("CS-KeyPair/CS-PrivateKey", Constants.TYPE_PKI);
        byte[] signature = getSignature(privateKey, ac);

        //return bytesToHex(signature);
        return signature;
    }

    public byte[] getPublicKey() throws Exception{
        PublicKey publicKey = this.getPublic("CS-KeyPair/CS-PublicKey", Constants.TYPE_PKI);
        byte[] publicKeyBytes = publicKey.getEncoded();

        return publicKeyBytes;
    }

    public byte[] encryptWithRsa(byte[] data, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public byte[] decryptWithRsa(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    //SK cs-tgs 생성
    public Key getSecretEncryptionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.init(128, random);
        return generator.generateKey();
    }

    //CBC 암호화를 위해 IV 생성
    public IvParameterSpec getIvParameterSpec() throws Exception {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    //CBC 운용모드 AES 암호화
    public byte[] encryptWithAes(Key sk, IvParameterSpec iv, String plainText) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, sk, iv);
        byte[] encryptData = cipher.doFinal(plainText.getBytes());

        return encryptData;
    }

    public byte[] decryptWithAes(Key sk, IvParameterSpec iv, byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, sk, iv);
        byte[] decryptedData = cipher.doFinal(cipherText);
        return decryptedData;
    }
}
