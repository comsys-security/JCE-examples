package RSA;
import com.ncipher.jutils.HexFunctions;
import com.ncipher.provider.km.nCipherKM;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;

class RSA_gen {

        public static void main(String[] args) throws GeneralSecurityException, IOException {
		
		char[] CARDSET_PASSPHRASE = "comsys2019".toCharArray();
		String keyalias = "RSA Key";

		Security.addProvider(new nCipherKM());
		
		// Create a cardset protected keystore.
        //System.setProperty("protect", "softcard:284141b6fc9843613c68bf97b3bb8e8cf1f6a102");
        System.out.println("Sample Java Application");
        System.out.println("nShield JCE");
        System.out.println("for testing only");

        // define variable for nShield JCE
        String provider = "nCipherKM";
        String algorithm = "RSA";
        int keyLength;
        keyLength = 2048;

        // generate RSA key
        System.out.println("Generate RSA key...");
        KeyPairGenerator keyPairGen = null;
        try {
                 keyPairGen = KeyPairGenerator.getInstance(algorithm, provider);
                 //keyPairGen = KeyPairGenerator.getInstance(algorithm);
        } catch (Exception e) {
                System.err.println(e.getClass().getName()+":"+e.getMessage());
				System.exit(1);
        }
        keyPairGen.initialize(keyLength);
        KeyPair RSAKeyPair = keyPairGen.generateKeyPair();
		PrivateKey privKey = RSAKeyPair.getPrivate();
		PublicKey pubKey = RSAKeyPair.getPublic();
		System.out.println("Generated an RSA keypair of type: " + privKey.getAlgorithm());
		System.out.println("The encoded public key is: " + HexFunctions.byte2hex(pubKey.getEncoded()));
		
		KeyStore ks = KeyStore.getInstance("ncipher.sworld", "nCipherKM");
		ks.load(null, CARDSET_PASSPHRASE);
		System.out.println("Created keystore");

		// Add the public RSA key to the keystore.
		ks.setKeyEntry(keyalias , pubKey, CARDSET_PASSPHRASE, null);
		System.out.println("Added RSAPublicKey to keystore");

		// Generate an RSA Key pair for the certificate
		KeyPairGenerator RSAkpg = KeyPairGenerator.getInstance("RSA", "nCipherKM");
		KeyPair RSAkeyPair = RSAkpg.generateKeyPair();
		final Certificate certificate = makeDummyCertificate(RSAkeyPair, "nCipherKM");
		Certificate[] certChain = new Certificate[] {certificate};

		// Add the private RSA key to the keystore.
		ks.setKeyEntry(keyalias, privKey, CARDSET_PASSPHRASE, certChain);
		System.out.println("Added RSAPrivateKey to keystore");

		// Store the KeyStore. The store method saves the keys in the KeyStore
		// into the main nCipher security world.
		FileOutputStream out = new FileOutputStream("keystore.dat");
		ks.store(out, CARDSET_PASSPHRASE);
		out.close();
		System.out.println("Saved keys in keystore to Security World");
        }
		
	   /**
	   * Make a dummy certificate for storing a PrivateKey in a KeyStore
	   *
	   * @param aKeyPair used to get the PublicKey
	   * @param aProviderName used for constructing the superclass
	   * @return a dummy certificate, which will refuse to verify any key, and should not be used in a
	   *     production system. This is a stub implementation which provides just enough functionality
	   *     to permit us to store a PrivateKey in a KeyStore.
	   * @see java.security.Certificate
	   * @see java.security.KeyPair
	   * @see java.security.KeyStore
	   * @see java.security.PrivateKey
	   * @see java.security.PublicKey
	   */
	  static Certificate makeDummyCertificate(final KeyPair aKeyPair, final String aProviderName) {
		final Certificate theResult =
			new Certificate(aProviderName) {
			  @Override
			  public String toString() {
				final String theObjectString = ((Object) this).toString();
				final String theResult =
					"Dummy Certificate (do not use in production): " + theObjectString;
				return theResult;
			  }

			  @Override
			  public byte[] getEncoded() {
				final byte[] theResult = new byte[0];
				return theResult;
			  }

			  /** Verify nothing -- this is a failsafe against misuse */
			  @Override
			  public void verify(final PublicKey aKey) throws SignatureException {
				failVerification();
			  }

			  /** Verify nothing -- this is a failsafe against misuse */
			  @Override
			  public void verify(final PublicKey aKey, final String aSignatureProvider)
				  throws SignatureException {
				failVerification();
			  }

			  @Override
			  public PublicKey getPublicKey() {
				return aKeyPair.getPublic();
			  }

			  void failVerification() throws SignatureException {
				final String theReason = "Dummy certificate used, cannot verify anything";
				final SignatureException theFail = new SignatureException(theReason);
				throw theFail;
			  }
			};
		return theResult;
	  }
}
