package RNG;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import com.ncipher.provider.km.nCipherKM;


class GenRNG {
	
	/*NONCE */
	public static final int NONCE_LENGTH = 12; // in bytes
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {

		Security.addProvider(new nCipherKM());
		
		System.out.println("Test RNG ...");
		byte[] bytes = new byte[1024];
		SecureRandom random = SecureRandom.getInstance("RNG", "nCipherKM");
		random.nextBytes(bytes);
		System.out.println("Test RNG Done.");
		
		byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        System.out.println(nonce);
	}
}

