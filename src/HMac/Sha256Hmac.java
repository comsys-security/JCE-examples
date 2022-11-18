package HMac;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.Signature;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.ncipher.provider.km.nCipherKM;

public class Sha256Hmac {
	/** 마스터 키의 이름 */
	public static String MASTER_KEY_NAME = "M_KEY";
	/** 키 파일 이름 */
	public static String KEY_FILE_NAME = "keystore.dat";
	/** 키 길이 */
	public static final int Sha256Hmac_KEY_SIZE = 128; // in bits
	/** 키 알고리즘 */
	public static String algorithm = "HmacSHA256";
	
	public static String provider = "nCipherKM";
	
	public static KeyStore ks = null;


	public static void main(String[] args) throws GeneralSecurityException, IOException, InterruptedException {
		
		
		SecretKey sk = null;   //Hmac을 생성할 Key의 핸들값을 저장할 객체  
		char[] passwd = "comsys2019".toCharArray();
		//System.setProperty("protect", "softcard:2e5f6fd63817365c656c26e23fd57f8598401ae7");
		// Check file.
		File f = new File(KEY_FILE_NAME);
		Security.addProvider(new nCipherKM());
		
		//keystore가 존재 하는지 확인 없다면 생성...
		if (!f.exists()) {
			System.out.println("Create keystore...");
			
			/* $JAVA_HOEM/jre/lib/security/java.security 파일의 keystore.type=nCipher.sworld 로 수정하였을 경우 */
			ks = KeyStore.getInstance("ncipher.sworld", "nCipherKM");
		
			/* $JAVA_HOEM/jre/lib/security/java.security 파일의 keystore.type=jks 일 경우 (default) */
			//ks = KeyStore.getInstance(KeyStore.getDefaultType(), provider);
			ks.load(null, passwd);
		}
		else {
			System.out.println("Open keystore...");
			ks = KeyStore.getInstance("ncipher.sworld", "nCipherKM");
			
			/* $JAVA_HOEM/jre/lib/security/java.security 파일의 keystore.type=jks 일 경우 (default) */
			//ks = KeyStore.getInstance(KeyStore.getDefaultType(), provider);
			FileInputStream inTemp = new FileInputStream(KEY_FILE_NAME);
			ks.load(inTemp, passwd);
		}
		//같은 이름의 사용중인 Key가 있는지 확인
		if (ks.getKey(MASTER_KEY_NAME, passwd) != null) {
			System.out.println("aready exists key alias.");				
		}
		
		else {
			System.out.println("Creating master key....");
			byte [] keyBytes = new byte [] { (byte)0xA4 ,(byte)0xD0 ,(byte)0xF8 ,(byte)0xFB ,(byte)0x49 ,(byte)0x58 ,(byte)0x67 ,(byte)0x5D ,(byte)0xBA ,(byte)0x40 ,
					                         (byte)0xAB ,(byte)0x1F ,(byte)0x37 ,(byte)0x22 ,(byte)0xEF ,(byte)0x0D ,(byte)0xC1 ,(byte)0xD0 ,(byte)0xF8 ,(byte)0x6B ,
					                         (byte)0x49 ,(byte)0x58 ,(byte)0x67 ,(byte)0x0D ,(byte)0xBA ,(byte)0x40 ,(byte)0xAB ,(byte)0x1F ,(byte)0x37 ,(byte)0x52 ,
					                         (byte)0xEF ,(byte)0x0D  }; // actual keys replaced with dummies.

			SecretKey keySpec = new SecretKeySpec(keyBytes, algorithm);
			//SecretKey key = kg.generateKey();
			    
		
			ks.setKeyEntry(MASTER_KEY_NAME, keySpec, passwd, null);
			System.out.println("Succeed import key.");
			
			FileOutputStream stream = new FileOutputStream(f);
			ks.store(stream, passwd);
			stream.close();
		}
			
		sk = (SecretKey)ks.getKey(MASTER_KEY_NAME, passwd);
			
		if(sk == null)
		{
			System.out.println("The key " + MASTER_KEY_NAME + " doesn't exist in the keystore " + KEY_FILE_NAME);
			return;
		}
		else
			System.out.println("The selected key alias : " + MASTER_KEY_NAME);
			
		System.out.print( "Attempting to export the Hmac key ... \n" );   

			
			    
		byte[] data = {(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0x00,(byte)0x00,
				       (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00};
				
		/* Perform HMAC using SHA-256. */
		Mac m = Mac.getInstance("HmacSHA256");
	    m.init(sk);
	    byte[] hmac = m.doFinal(data);
		System.out.println( "Create HMAC." );	
			
		System.out.println( "hmac byte : "+hmac.length );
		Encoder b64 = Base64.getEncoder();
		String base64 = b64.encodeToString(hmac);
			
		System.out.println( "Encoding Sign data." );
		System.out.println( "========================================================" );
		System.out.println(base64);	
		System.out.println( "========================================================" );
		byte [] saveText = base64.getBytes();
		String szFileName = "generated HMac.txt";
		File file = new File(szFileName);
		OutputStream out = new FileOutputStream(file);
		out.write(saveText);
		out.close();
		System.out.println( "파일 저장을 완료했습니다.");
		
	}
}

			
			
	