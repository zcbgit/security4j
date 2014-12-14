package security4j.util.coders;

import java.io.IOException;

import javax.crypto.SecretKey;


public class TestCoder {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {

			TestCoder coder = new TestCoder();
			coder.testPBE(PBECoder.PBEWithSHA1AndRC2_40);
 	        
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
        System.err.println("原文:\t" + inputStr);  
        byte[] keyData = DESCoder.getKey("D:/des.dat");
        System.err.println("密钥:\t" + keyData);  
  
        byte[] inputData = inputStr.getBytes();  
        inputData = DESCoder.encrypt(inputData, keyData, algorithm);  
  
        System.err.println("加密后:\t" + BaseCoder.encryptBASE64(inputData));  
  
        byte[] outputData = DESCoder.decrypt(inputData, keyData, algorithm);  
        String outputStr = new String(outputData);  
  
        System.err.println("解密后:\t" + outputStr); 		
	}
	
	//测试PBE算法
	public void testPBE(String algorithm) throws Exception {

        String inputStr = "abc";  
        System.err.println("原文: " + inputStr);  
        byte[] input = inputStr.getBytes();  
  
        String pwd = "efg";  
        System.err.println("密码: " + pwd);  
  
        byte[] salt = PBECoder.initSalt();  
  
        byte[] data = PBECoder.encrypt(input, pwd, salt, algorithm);  
  
        System.err.println("加密后: " + BaseCoder.encryptBASE64(data));  
  
        byte[] output = PBECoder.decrypt(data, pwd, salt,algorithm);  
        String outputStr = new String(output);  
  
        System.err.println("解密后: " + outputStr); 		
	}
	
	//测试RSA算法
	public void testRSA() throws Exception {
		RSACoder.saveKey(RSACoder.generateNewKeyPair(), "D/publicKey.dat", "D/privateKey.dat");
		testPri2Pub();
		testPub2Pri();
	}
	
	private void testPub2Pri() throws Exception {
	    System.err.println("\n公钥加密——私钥解密");  
        String inputStr = "";
        for (int i = 0; i < 1024; i++) {
			inputStr += "a";
		}
        byte[] data = inputStr.getBytes();  
  
        byte[] encodedData = RSACoder.encryptByPublicKey(data, RSACoder.getPublicKey("D:/publicKey.dat"));  
  
        byte[] decodedData = RSACoder.decryptByPrivateKey(encodedData,  
                RSACoder.getPrivateKey("D:/privateKey.dat"));  
  
        String outputStr = new String(decodedData);  
        System.err.println("加密前: " + inputStr + "\n" + "解密后: " + outputStr); 		
	}
	
	private void testPri2Pub() throws Exception {
        System.err.println("\n私钥加密——公钥解密"); 
        String inputStr = ""; 
        for (int i = 0; i < 1024; i++) {
			inputStr += "a";
		}
        byte[] data = inputStr.getBytes();  
        byte[] encodedData = RSACoder.encryptByPrivateKey(data, RSACoder.getPrivateKey("D:/privateKey.dat"));  
        byte[] decodedData = RSACoder  
                .decryptByPublicKey(encodedData, RSACoder.getPublicKey("D:/publicKey.dat"));  
  
        String outputStr = new String(decodedData);  
        System.err.println("加密前: " + inputStr + "\n" + "解密后: " + outputStr);  
  
        System.err.println("私钥签名——公钥验证签名");  
        // 产生签名  
        String sign = new String(RSACoder.sign(encodedData, RSACoder.getPrivateKey("D:/privateKey.dat")));  
        System.err.println("签名:\r" + sign);  
  
        // 验证签名  
        boolean status = RSACoder.verify(encodedData, RSACoder.getPublicKey("D:/publicKey.dat"), sign.getBytes());  
        System.err.println("状态:\r" + status); 		
	}

}
