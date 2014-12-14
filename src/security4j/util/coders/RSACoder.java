package security4j.util.coders;
import java.io.ByteArrayOutputStream;
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;


public class RSACoder {
	private static final String KEY_ALGORITHM = "RSA";
	private static final String SIGNATURE_ALGORITHM = "MD5withRSA";
	//最大的明文长度不能超过117
	private static final int MAX_ENCRYPT_BLOCK_SIZE = 117;
	public static final int KEY_LENGTH_MIN = 512;
	public static final int KEY_LENGTH_1024 = 1024;
	public static final int KEY_LENGTH_2048 = 2048;
	public static final int KEY_LENGTH_MAX = KEY_LENGTH_2048;

	/**
	 * 用私钥对信息生成数字签名
	 * 
	 * @param data
	 *            加密数据
	 * @param privateKey
	 *            未经BASE64解码的私钥数据
	 * 
	 * @return byte[]
	 * 				签名后的数据
	 * @throws Exception
	 */
	public static byte[] sign(byte[] data, byte[] privateKey) throws Exception {
		// 解密由base64编码的私钥
		byte[] keyBytes = BaseCoder.decryptBASE64(privateKey);

		// 构造PKCS8EncodedKeySpec对象
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取私钥匙对象
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 用私钥对信息生成数字签名
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
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
	 *            未经BASE64解码码公钥数据
	 * @param sign
	 *            经数字签名后的数据
	 * 
	 * @return 校验成功返回true 失败返回false
	 * @throws Exception
	 * 
	 */
	public static boolean verify(byte[] data, byte[] publicKey, byte[] sign)
			throws Exception {

		// 解密由base64编码的公钥
		byte[] keyBytes = BaseCoder.decryptBASE64(publicKey);

		// 构造X509EncodedKeySpec对象
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

		// KEY_ALGORITHM 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

		// 取公钥匙对象
		PublicKey pubKey = keyFactory.generatePublic(keySpec);

		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(pubKey);
		signature.update(data);

		// 验证签名是否正常
		return signature.verify(BaseCoder.decryptBASE64(sign));
	}

	
	/**
	 * 解密<br>
	 * 用私钥解密
	 * 
	 * @param data
	 * 			须解密数据
	 * @param key
	 * 			未经过BASE64解码的私钥数据
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data, byte[] key)
			throws Exception {
		// 对密钥解密
		byte[] keyBytes = BaseCoder.decryptBASE64(key);

		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		RSAPrivateKey privateKey = (RSAPrivateKey)keyFactory.generatePrivate(pkcs8KeySpec);

		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		int datalength = data.length;
		//获取密钥长度再计算对应的最大密文长度，向上取整
		int subLength = (int) Math.ceil((double)privateKey.getModulus().toString(2).length() / 8);

		ByteArrayOutputStream decryptData = new ByteArrayOutputStream();
		for (int i = 0; i < datalength; i += subLength) {
			if (datalength - i > subLength) {
				decryptData.write(cipher.doFinal(data, i, subLength));
			} else {
				decryptData.write(cipher.doFinal(data, i, datalength - i));
			}
			decryptData.flush();
		}
		
		return decryptData.toByteArray();
	}

	/**
	 * 解密<br>
	 * 用公钥解密
	 * 
	 * @param data
	 * 			须解密数据
	 * @param key
	 * 			未经过BASE64解码的公钥数据
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, byte[] key)
			throws Exception {
		// 对密钥解密
		byte[] keyBytes = BaseCoder.decryptBASE64(key);

		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		RSAPublicKey publicKey = (RSAPublicKey)keyFactory.generatePublic(x509KeySpec);
		// 对数据解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		//每一组解密数据不能超过密钥长度个字节
		int datalength = data.length;
		//获取密钥长度再计算对应的最大密文长度，向上取整
		int subLength = (int) Math.ceil((double)publicKey.getModulus().toString(2).length() / 8);

		ByteArrayOutputStream decryptData = new ByteArrayOutputStream();
		for (int i = 0; i < datalength; i += subLength) {
			if (datalength - i > subLength) {
				decryptData.write(cipher.doFinal(data, i, subLength));
			} else {
				decryptData.write(cipher.doFinal(data, i, datalength - i));
			}
			decryptData.flush();
		}
		return decryptData.toByteArray();
	}

	/**
	 * 加密<br>
	 * 用公钥加密
	 * 
	 * @param data
	 * 			须加密数据
	 * @param key
	 * 			未经BASE64解码公钥数据
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, byte[] key)
			throws Exception {
		// 对公钥解密
		byte[] keyBytes = BaseCoder.decryptBASE64(key);

		// 取得公钥
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		RSAPublicKey publicKey = (RSAPublicKey)keyFactory.generatePublic(x509KeySpec);
		// 对数据分段加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);		
		
		int datalength = data.length;
		//获取密钥长度再计算对应的最大明文长度，每组数据的长度不能超过117或者，密钥长度-11个字节
		int subLength = publicKey.getModulus().toString(2).length() / 8 - 11;

		if (subLength > MAX_ENCRYPT_BLOCK_SIZE) {
			subLength = MAX_ENCRYPT_BLOCK_SIZE;
		}
		ByteArrayOutputStream encryptData = new ByteArrayOutputStream();
		for (int i = 0; i < datalength; i += subLength) {
			if (datalength - i > subLength) {
				encryptData.write(cipher.doFinal(data, i, subLength));
			} else {
				encryptData.write(cipher.doFinal(data, i, datalength - i));
			}
			encryptData.flush();
		}
		return encryptData.toByteArray();
	}

	/**
	 * 加密<br>
	 * 用私钥加密
	 * 
	 * @param data
	 * 			须加密数据
	 * @param key
	 * 			未经BASE64解码的私钥数据
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, byte[] key)
			throws Exception {
		// 对密钥解密
		byte[] keyBytes = BaseCoder.decryptBASE64(key);

		// 取得私钥
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		RSAPrivateKey privateKey = (RSAPrivateKey)keyFactory.generatePrivate(pkcs8KeySpec);
		// 对数据分段加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);		
		//每组数据的长度不能超过密钥长度-11个字节
		int datalength = data.length;
		//获取密钥长度再计算对应的最大明文长度
		int subLength = privateKey.getModulus().toString(2).length() / 8 - 11;
		if (subLength > MAX_ENCRYPT_BLOCK_SIZE) {
			subLength = MAX_ENCRYPT_BLOCK_SIZE;
		}

		ByteArrayOutputStream encryptData = new ByteArrayOutputStream();
		for (int i = 0; i < datalength; i += subLength) {
			if (datalength - i > subLength) {
				encryptData.write(cipher.doFinal(data, i, subLength));
			} else {
				encryptData.write(cipher.doFinal(data, i, datalength - i));
			}
			encryptData.flush();
		}

		return encryptData.toByteArray();
	}

	/**
	 * 取得私钥
	 * 
	 * @param keyPath
	 * 				公钥文件路径
	 * @return byte[]
	 * 				未经BASE64解码密钥数据
	 * @throws Exception
	 */
	public static byte[] getPrivateKey(String keyPath)
			throws Exception {
		File file = new File(keyPath);
		FileInputStream fis = new FileInputStream(file);
		byte[] key = new byte[fis.available()];
		fis.read(key);
		fis.close();
		return key;
	}

	/**
	 * 取得公钥
	 * 
	 * @param keyPath
	 * 				公钥文件路径
	 * @return byte[]
	 * 				未经BASE64解码公钥数据
	 * @throws Exception
	 */
	public static byte[] getPublicKey(String keyPath)
			throws Exception {
		File file = new File(keyPath);
		FileInputStream fis = new FileInputStream(file);
		byte[] key = new byte[fis.available()];
		fis.read(key);
		fis.close();
		return key;
	}

	/**
	 * 生成新密钥对，使用默认长度1024位
	 * 
	 * @return KeyPair 密钥对
	 * @throws Exception
	 */
	public static KeyPair generateNewKeyPair() throws Exception {
		return generateNewKeyPair(KEY_LENGTH_1024);
	}
	
	/**
	 * 生成新密钥对，可指定密钥长度
	 * 
	 * @param keyLength
	 * 				 密钥长度96-2048
	 * @return KeyPair 
	 * 				 密钥对
	 * @throws Exception
	 */
	public static KeyPair generateNewKeyPair(int keyLength) throws Exception {

		KeyPairGenerator keyPairGen = KeyPairGenerator
				.getInstance(KEY_ALGORITHM);
		String random = "" + System.currentTimeMillis();
		keyPairGen.initialize(keyLength,  new SecureRandom(random.getBytes()));
		KeyPair keyPair = keyPairGen.generateKeyPair();

//		// 公钥
//		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
//
//		// 私钥
//		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		return keyPair;
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
