package security4j.util.coders;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 *  数字签名算法
 *
 */
public class DSACoder { 
    /** 
     * 默认密钥字节数 
     *  
     * <pre> 
     * DSA  
     * Default Keysize 1024   
     * Keysize must be a multiple of 64, ranging from 512 to 1024 (inclusive). 
     * </pre> 
     */  
    private static final int KEY_SIZE = 1024;  
  
    /** 
     * 用私钥对信息生成数字签名 
     *  
     * @param data 
     *            加密数据 
     * @param privateKey 
     *            私钥 
     *  
     * @return 
     * @throws Exception 
     */  
    public static byte[] sign(byte[] data, byte[] privateKey) throws Exception {  
        // 解密由base64编码的私钥  
        byte[] keyBytes = BaseCoder.decryptBASE64(privateKey);  
  
        // 构造PKCS8EncodedKeySpec对象  
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
  
        // KEY_"DSA" 指定的加密算法  
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");  
  
        // 取私钥匙对象  
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);  
  
        // 用私钥对信息生成数字签名  
        Signature signature = Signature.getInstance(keyFactory.getAlgorithm());  
        signature.initSign(priKey);  
        signature.update(data);  
  
        return BaseCoder.encryptBASE64(signature.sign());  
    }  
  
    /** 
     * 校验数字签名 
     *  
     * @param data 
     *            加密数据 
     * @param publicKey 
     *            公钥 
     * @param sign 
     *            数字签名 
     *  
     * @return 校验成功返回true 失败返回false 
     * @throws Exception 
     *  
     */  
    public static boolean verify(byte[] data, byte[] publicKey, String sign)  
            throws Exception {  
  
        // 解密由base64编码的公钥  
        byte[] keyBytes = BaseCoder.decryptBASE64(publicKey);  
  
        // 构造X509EncodedKeySpec对象  
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);  
  
        // "DSA" 指定的加密算法  
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");  
  
        // 取公钥匙对象  
        PublicKey pubKey = keyFactory.generatePublic(keySpec);  
  
        Signature signature = Signature.getInstance(keyFactory.getAlgorithm());  
        signature.initVerify(pubKey);  
        signature.update(data);  
  
        // 验证签名是否正常  
        return signature.verify(BaseCoder.decryptBASE64(sign));  
    }  
  
    /** 
     * 生成密钥 
     *  
     * @param seed 
     *            种子 
     * @return 密钥对 
     * @throws Exception 
     */  
    public static KeyPair generateKeyPair() throws Exception {  
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");  
        // 初始化随机产生器  
        String seed = "" + System.currentTimeMillis();
        SecureRandom secureRandom = new SecureRandom();  
        secureRandom.setSeed(seed.getBytes());  
        keygen.initialize(KEY_SIZE, secureRandom);  
  
        KeyPair keys = keygen.genKeyPair();  
  
//        DSAPublicKey publicKey = (DSAPublicKey) keys.getPublic();  
//        DSAPrivateKey privateKey = (DSAPrivateKey) keys.getPrivate();   
  
        return keys;  
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
