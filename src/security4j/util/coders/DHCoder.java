package security4j.util.coders;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
  
/** 
 * DH安全编码组件 
 *  
 */  
public abstract class DHCoder {
  
    /** 
     * 默认密钥字节数 
     *  
     * <pre> 
     * DH 
     * Default Keysize 1024   
     * Keysize must be a multiple of 64, ranging from 512 to 1024 (inclusive). 
     * </pre> 
     */  
    private static final int KEY_SIZE = 1024;  
  
    /** 
     * DH加密下需要一种对称加密算法对数据加密，这里我们使用DES，也可以使用其他对称加密算法。 
     */  
    public static final String SECRET_ALGORITHM = "DES";  
  
    /** 
     * 初始化甲方密钥 
     *  
     * @return 
     * @throws Exception 
     */  
    public static KeyPair generateKeyPairA() throws Exception {  
        KeyPairGenerator keyPairGenerator = KeyPairGenerator  
                .getInstance("DH");  
        keyPairGenerator.initialize(KEY_SIZE);  
  
        KeyPair keyPair = keyPairGenerator.generateKeyPair();  
//        // 甲方公钥  
//        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();  
//        // 甲方私钥  
//        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();  
        return keyPair;  
    }  
  
    /** 
     * 初始化乙方密钥 
     *  
     * @param key 
     *            甲方公钥 
     * @return 
     * @throws Exception 
     */  
    public static KeyPair generateKeyPairB(byte[] key) throws Exception {  
        // 解析甲方公钥  
        byte[] keyBytes = BaseCoder.decryptBASE64(key);  
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);  
        KeyFactory keyFactory = KeyFactory.getInstance("DH");  
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);  
  
        // 由甲方公钥构建乙方密钥  
        DHParameterSpec dhParamSpec = ((DHPublicKey) pubKey).getParams();  
  
        KeyPairGenerator keyPairGenerator = KeyPairGenerator  
                .getInstance(keyFactory.getAlgorithm());  
        keyPairGenerator.initialize(dhParamSpec);  
  
        KeyPair keyPair = keyPairGenerator.generateKeyPair();  
  
//        // 乙方公钥  
//        DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();  
//        // 乙方私钥  
//        DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();   
  
        return keyPair;  
    }  
  
    /** 
     * 加密<br> 
     *  
     * @param data 
     *            待加密数据 
     * @param publicKey 
     *            甲(乙)方公钥 
     * @param privateKey 
     *            乙（甲）方私钥 
     * @return 
     * @throws Exception 
     */  
    public static byte[] encrypt(byte[] data, byte[] publicKey,  
    		byte[] privateKey) throws Exception {  
  
        // 生成本地密钥  
        SecretKey secretKey = getSecretKey(publicKey, privateKey);  
  
        // 数据加密  
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());  
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);  
  
        return cipher.doFinal(data);  
    }  
  
    /** 
     * 解密<br> 
     *  
     * @param data 
     *            待解密数据 
     * @param publicKey 
     *            乙（甲）方公钥 
     * @param privateKey 
     *            甲（乙）方私钥 
     * @return 
     * @throws Exception 
     */  
    public static byte[] decrypt(byte[] data, byte[] publicKey,  
    		byte[] privateKey) throws Exception {  
  
        // 生成本地密钥  
        SecretKey secretKey = getSecretKey(publicKey, privateKey);  
        // 数据解密  
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());  
        cipher.init(Cipher.DECRYPT_MODE, secretKey);  
  
        return cipher.doFinal(data);  
    }  
  
    /** 
     * 构建密钥 
     *  
     * @param publicKey 
     *            公钥 
     * @param privateKey 
     *            私钥 
     * @return 
     * @throws Exception 
     */  
    private static SecretKey getSecretKey(byte[] publicKey, byte[] privateKey)  
            throws Exception {  
        // 初始化公钥  
        byte[] pubKeyBytes = BaseCoder.decryptBASE64(publicKey);  
  
        KeyFactory keyFactory = KeyFactory.getInstance("DH");  
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyBytes);  
        PublicKey pubKey = keyFactory.generatePublic(x509KeySpec);  
  
        // 初始化私钥  
        byte[] priKeyBytes = BaseCoder.decryptBASE64(privateKey);  
  
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(priKeyBytes);  
        Key priKey = keyFactory.generatePrivate(pkcs8KeySpec);  
  
        KeyAgreement keyAgree = KeyAgreement.getInstance(keyFactory  
                .getAlgorithm());  
        keyAgree.init(priKey);  
        keyAgree.doPhase(pubKey, true);  
  
        // 生成本地密钥  
        SecretKey secretKey = keyAgree.generateSecret(SECRET_ALGORITHM);  
  
        return secretKey;  
    }  
  
    /** 
     * 取得未经BASE64解码的密钥信息 
     *  
     * @param keyPath 
     * @return 
     * @throws Exception 
     */  
    public static byte[] getKey(String keyPath)  
            throws Exception {   
		File file = new File(keyPath);
		FileInputStream fis = new FileInputStream(file);
		byte[] key = new byte[fis.available()];
		fis.read(key);
		fis.close();
		return key; 
    }   
    
	/**
	 * 将密钥对保存到指定文件中
	 * 
	 * @param keyPair 
	 * 				要保存的密钥对
	 * @param publicKeyPath 
	 * 				公钥保存路径
	 * @param privateKeyPath 
	 * 				私钥保存路径
	 * @throws IOException
	 * @throws Exception
	 */
	
	public static void saveKey(KeyPair keyPair, String publicKeyPath,   
            String privateKeyPath) throws IOException, Exception {   
        PublicKey pubkey = keyPair.getPublic();   
        PrivateKey prikey = keyPair.getPrivate();   
  
        // save public key   
        File pubFile  = new File(publicKeyPath);
        FileOutputStream pubs = new FileOutputStream(pubFile);
        pubs.write(BaseCoder.encryptBASE64(pubkey.getEncoded()));
        pubs.flush();
        pubs.close();
        // save private key   
        File prifile  = new File(privateKeyPath);
        FileOutputStream pris = new FileOutputStream(prifile);
        pris.write(BaseCoder.encryptBASE64(prikey.getEncoded()));
        pris.flush();
        pris.close();  
    } 
} 
