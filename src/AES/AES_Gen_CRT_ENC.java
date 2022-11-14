package AES;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.ncipher.provider.km.nCipherKM;

//주의!!! AES 키는 HSM 메모리에 생성되며, Store 되지 않음.
public class AES_Gen_CRT_ENC {
	
	static String provider = "nCipherKM";

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		Security.addProvider(new nCipherKM());
		AES_Gen_CRT_ENC modeTest = new AES_Gen_CRT_ENC();
		modeTest.run();
	}
	
	public void run() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		//System.setProperty("protect", "softcard:284141b6fc9843613c68bf97b3bb8e8cf1f6a102");
		
		SecretKey secretKey = createSecretKey();
		
		KeyPair keyPair = createKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		
		//byte[] privateKeyBytes = privateKey.getEncoded();
		//System.out.println(HexStringConverter.hexToString(privateKeyBytes));
		//System.out.println("privateKeyBytes.length: " + privateKeyBytes.length);
		
		byte[] publicKeyBytes = publicKey.getEncoded();
		System.out.println(HexStringConverter.hexToString(publicKeyBytes));
		System.out.println("publicKeyBytes.length: " + publicKeyBytes.length);
		
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", provider);
		byte[] iv = new byte[16];
		Arrays.fill( iv, (byte) 0 );
		
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
		
		//byte[] encPrivateKeyBytes = cipher.doFinal(privateKeyBytes);
		//System.out.println(HexStringConverter.hexToString(encPrivateKeyBytes));
		//System.out.println("encPrivateKeyBytes.length: " + encPrivateKeyBytes.length);
		
		byte[] encPublicKeyBytes = cipher.doFinal(publicKeyBytes);
		System.out.println(HexStringConverter.hexToString(encPublicKeyBytes));
		System.out.println("encPublicKeyBytes.length: " + encPublicKeyBytes.length);
	}
	
	protected SecretKey createSecretKey()throws NoSuchProviderException {
		
		SecretKey secretKey = null;
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES","nCipherKM");
			keyGen.init(256);
			secretKey = keyGen.generateKey();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		return secretKey;
	}
	
	protected KeyPair createKeyPair()throws NoSuchProviderException{
		KeyPair keyPair = null;
		
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA","nCipherKM");
			keyGen.initialize(2048, new SecureRandom());
			keyPair = keyGen.generateKeyPair();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		
		return keyPair;
	}

}
