package security4j.util.coders;

import java.io.IOException;
import java.security.KeyPair;

import javax.crypto.SecretKey;


public class TestCoder {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {

			TestCoder coder = new TestCoder();
			coder.testDSA();
 	        
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	// 测试DES算法
	public void testDES(String algorithm) throws Exception {

		SecretKey key = DESCoder.generateKey(algorithm);
		DESCoder.saveKey(key, "D:/des.dat");
        String inputStr = "";
        for (int i = 0; i < 1024; i++) {
			inputStr += "a";
		}
        System.out.println("原文:\t" + inputStr);  
        byte[] keyData = DESCoder.getKey("D:/des.dat");
        System.out.println("密钥:\t" + keyData);  
  
        byte[] inputData = inputStr.getBytes();  
        inputData = DESCoder.encrypt(inputData, keyData, algorithm);  
  
        System.out.println("加密后:\t" + BaseCoder.encryptBASE64(inputData));  
  
        byte[] outputData = DESCoder.decrypt(inputData, keyData, algorithm);  
        String outputStr = new String(outputData);  
  
        System.out.println("解密后:\t" + outputStr); 		
	}
	
	//测试PBE算法
	public void testPBE(String algorithm) throws Exception {

        String inputStr = "abc";  
        System.out.println("原文: " + inputStr);  
        byte[] input = inputStr.getBytes();  
  
        String pwd = "efg";  
        System.out.println("密码: " + pwd);  
  
        byte[] salt = PBECoder.initSalt();  
  
        byte[] data = PBECoder.encrypt(input, pwd, salt, algorithm);  
  
        System.out.println("加密后: " + BaseCoder.encryptBASE64(data));  
  
        byte[] output = PBECoder.decrypt(data, pwd, salt,algorithm);  
        String outputStr = new String(output);  
  
        System.out.println("解密后: " + outputStr); 		
	}
	
	//测试RSA算法
	public void testRSA() throws Exception {
		RSACoder.saveKey(RSACoder.generateNewKeyPair(), "D/publicKey.dat", "D/privateKey.dat");
		testPri2Pub();
		testPub2Pri();
	}
	
	private void testPub2Pri() throws Exception {
	    System.out.println("\n公钥加密——私钥解密");  
        String inputStr = "";
        for (int i = 0; i < 1024; i++) {
			inputStr += "a";
		}
        byte[] data = inputStr.getBytes();  
  
        byte[] encodedData = RSACoder.encryptByPublicKey(data, RSACoder.getPublicKey("D:/publicKey.dat"));  
  
        byte[] decodedData = RSACoder.decryptByPrivateKey(encodedData,  
                RSACoder.getPrivateKey("D:/privateKey.dat"));  
  
        String outputStr = new String(decodedData);  
        System.out.println("加密前: " + inputStr + "\n" + "解密后: " + outputStr); 		
	}
	
	private void testPri2Pub() throws Exception {
        System.out.println("\n私钥加密——公钥解密"); 
        String inputStr = ""; 
        for (int i = 0; i < 1024; i++) {
			inputStr += "a";
		}
        byte[] data = inputStr.getBytes();  
        byte[] encodedData = RSACoder.encryptByPrivateKey(data, RSACoder.getPrivateKey("D:/privateKey.dat"));  
        byte[] decodedData = RSACoder  
                .decryptByPublicKey(encodedData, RSACoder.getPublicKey("D:/publicKey.dat"));  
  
        String outputStr = new String(decodedData);  
        System.out.println("加密前: " + inputStr + "\n" + "解密后: " + outputStr);  
  
        System.out.println("私钥签名——公钥验证签名");  
        // 产生签名  
        String sign = new String(RSACoder.sign(encodedData, RSACoder.getPrivateKey("D:/privateKey.dat")));  
        System.out.println("签名:\r" + sign);  
  
        // 验证签名  
        boolean status = RSACoder.verify(encodedData, RSACoder.getPublicKey("D:/publicKey.dat"), sign.getBytes());  
        System.out.println("状态:\r" + status); 		
	}

	public void testDH() throws Exception {
        // 生成甲方密钥对儿  
        KeyPair aKeys = DHCoder.generateKeyPairA();  
        String aPublicKey = new String(BaseCoder.encryptBASE64(aKeys.getPublic().getEncoded())); 
        String aPrivateKey = new String(BaseCoder.encryptBASE64(aKeys.getPrivate().getEncoded()));  
  
        System.out.println("甲方公钥:\r" + aPublicKey);  
        System.out.println("甲方私钥:\r" + aPrivateKey);  
          
        // 由甲方公钥产生本地密钥对儿  
        KeyPair bKeys = DHCoder.generateKeyPairB(aPublicKey.getBytes());  
        String bPublicKey = new String(BaseCoder.encryptBASE64(bKeys.getPublic().getEncoded()));  
        String bPrivateKey = new String(BaseCoder.encryptBASE64(bKeys.getPrivate().getEncoded()));  
          
        System.out.println("乙方公钥:\r" + bPublicKey);  
        System.out.println("乙方私钥:\r" + bPrivateKey);  
          
        String aInput = "abc ";  
        System.out.println("原文: " + aInput);  
  
        // 由甲方公钥，乙方私钥构建密文  
        byte[] aCode = DHCoder.encrypt(aInput.getBytes(), aPublicKey.getBytes(),  
                bPrivateKey.getBytes());  
  
        // 由乙方公钥，甲方私钥解密  
        byte[] aDecode = DHCoder.decrypt(aCode, bPublicKey.getBytes(), aPrivateKey.getBytes());  
        String aOutput = (new String(aDecode));  
  
        System.out.println("解密: " + aOutput);  
  
        System.out.println(" ===============反过来加密解密================== ");  
        String bInput = "def ";  
        System.out.println("原文: " + bInput);  
  
        // 由乙方公钥，甲方私钥构建密文  
        byte[] bCode = DHCoder.encrypt(bInput.getBytes(), bPublicKey.getBytes(),  
                aPrivateKey.getBytes());  
  
        // 由甲方公钥，乙方私钥解密  
        byte[] bDecode = DHCoder.decrypt(bCode, aPublicKey.getBytes(), bPrivateKey.getBytes());  
        String bOutput = (new String(bDecode));  
  
        System.out.println("解密: " + bOutput);		
	}
	
	public void testDSA() throws Exception {
        String inputStr = "abc";  
        byte[] data = inputStr.getBytes();  
  
        // 构建密钥  
        KeyPair keyPair = DSACoder.generateKeyPair();  
  
        // 获得密钥  
        String publicKey = new String(BaseCoder.encryptBASE64(keyPair.getPublic().getEncoded()));  
        String privateKey = new String(BaseCoder.encryptBASE64(keyPair.getPrivate().getEncoded()));
  
        System.out.println("公钥:\r" + publicKey);  
        System.out.println("私钥:\r" + privateKey);  
  
        // 产生签名  
        String sign = new String(DSACoder.sign(data, privateKey.getBytes()));  
        System.out.println("签名:\r" + sign);  
  
        // 验证签名  
        boolean status = DSACoder.verify(data, publicKey.getBytes(), sign);  
        System.out.println("状态:\r" + status);		
	}
}
