package security4j.util.coders;

import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BaseCoder {

	/**
	 * MAC算法可选以下多种算法
	 * 
	 * <pre>
	 * HmacMD5 
	 * HmacSHA1 
	 * HmacSHA256 
	 * HmacSHA384 
	 * HmacSHA512
	 * </pre>
	 */
	public static final String HMAC_MD5 	= "HmacMD5";
	public static final String HMAC_SHA1 	= "HmacSHA1";
	public static final String HMAC_SHA256 	= "HmacSHA256";
	public static final String HMAC_SHA384 	= "HmacSHA384";
	public static final String HMAC_SHA512 	= "HmacSHA512";

	/**
	 * BASE64解密
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptBASE64(String key) throws Exception {
		return Base64.getDecoder().decode(key);
	}

	/**
	 * BASE64解密
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptBASE64(byte[] key) throws Exception {
		return Base64.getDecoder().decode(key);
	}

	/**
	 * BASE64加密
	 * 
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptBASE64(byte[] key) throws Exception {
		return Base64.getEncoder().encode(key);
	}

	/**
	 * MD5(Message Digest algorithm
	 * 5，信息摘要算法)，是单向加密，任何数据加密后只会产生唯一的一个加密串，通常用来校验数据在传输过程中是否被修改。
	 * 
	 * @param data
	 *            须验证信息
	 * @return 经MD5加密后的结果
	 * @throws Exception
	 */
	public static byte[] encryptMD5(byte[] data) throws Exception {

		MessageDigest md5 = MessageDigest.getInstance("MD5");
		md5.update(data);

		return md5.digest();

	}

	/**
	 * SHA(Secure Hash
	 * Algorithm，安全散列算法)，是单向加密，任何数据加密后只会产生唯一的一个加密串，通常用来校验数据在传输过程中是否被修改。
	 * 
	 * @param data
	 *            须验证信息
	 * @return 经SHA加密后的结果
	 * @throws Exception
	 */
	public static byte[] encryptSHA(byte[] data) throws Exception {

		MessageDigest sha = MessageDigest.getInstance("SHA");
		sha.update(data);

		return sha.digest();

	}

	/**
	 * 初始化HMAC密钥
	 * 
	 * @param keyType
	 *            MAC算法可选以下多种算法
	 * <pre>
	 * HmacMD5 
	 * HmacSHA1 
	 * HmacSHA256 
	 * HmacSHA384 
	 * HmacSHA512  
	 * </pre> 
	 * @return
	 * @throws Exception
	 */
	public static byte[] initMacKey(String algorithm) throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);

		SecretKey secretKey = keyGenerator.generateKey();
		return encryptBASE64(secretKey.getEncoded());
	}

	/**
	 * HMAC(Hash Message Authentication
	 * Code，散列消息鉴别码)，是单向加密，任何数据加密后只会产生唯一的一个加密串，通常用来校验数据在传输过程中是否被修改。
	 *
	 * @param keyType
	 *            MAC算法可选以下多种算法
	 * <pre>
	 * HmacMD5 
	 * HmacSHA1 
	 * HmacSHA256 
	 * HmacSHA384 
	 * HmacSHA512  
	 * </pre>      
	 * @param data
	 *            验证数据
	 * @param key
	 *            未经BASE64解码的密钥信息
	 * @return byte[] 经HMAC加密后的结果
	 * @throws Exception
	 */
	public static byte[] encryptHMAC(byte[] data, byte[] key, String algorithm) throws Exception {
		SecretKey secretKey = new SecretKeySpec(decryptBASE64(key), algorithm);
		Mac mac = Mac.getInstance(secretKey.getAlgorithm());
		mac.init(secretKey);

		return mac.doFinal(data);
	}

}
