package EC;
import com.ncipher.jutils.HexFunctions;
import com.ncipher.provider.km.nCipherKM;

import java.security.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Base64.Encoder;




/**
 * ECDSA Key Generation example.
 *
 * <p>Demonstrates creation of a card-protected keystore and the creation of an ECDSA key pair.
 * Requires an OCS card with passphrase 'comsys2019'
 */
public class ECDSA_Gen_Sign {
  public static void main(String[] args) throws GeneralSecurityException, IOException {
    char[] CARDSET_PASSPHRASE = "comsys2019".toCharArray();
    String keyalias = "ECDSA Key";
    Security.addProvider(new nCipherKM());
    // Create a cardset protected keystore.
    //System.setProperty("protect", "softcard:e128c587cef300747fcd088243713881f7fe6eb7");

    // Signature and Ramdom classe
    Signature signer = null;
    SecureRandom random = null;
    Signature verifier = null;
    int nBytes = 100;     //Ramdom nBytes
	
    // Generate an ECDSA keypair
	  ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");  //secp256r1 curve
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "nCipherKM");
	  kpg.initialize(ecSpec);

    KeyPair keyPair = kpg.generateKeyPair();
    PrivateKey privKey = keyPair.getPrivate();
    PublicKey pubKey = keyPair.getPublic();

    System.out.println("Generated an ECDSA keypair of type: " + privKey.getAlgorithm());
    System.out.println("The encoded public key is: " + HexFunctions.byte2hex(pubKey.getEncoded()));

    KeyStore ks = KeyStore.getInstance("ncipher.sworld", "nCipherKM");
    ks.load(null, CARDSET_PASSPHRASE);
    System.out.println("Created keystore");

    // Add the public EC key to the keystore.
    ks.setKeyEntry(keyalias, pubKey, CARDSET_PASSPHRASE, null);
    System.out.println("Added ECDSAPublicKey to keystore");


	  // Generate an ECDSA certificate
    final Certificate certificate = makeDummyCertificate(keyPair, "nCipherKM");
    Certificate[] certChain = new Certificate[] {certificate};
    
    // Add the private EC key to the keystore.
    ks.setKeyEntry(keyalias , privKey, CARDSET_PASSPHRASE, certChain);
    System.out.println("Added ECDSAPrivateKey to keystore");
	
	  System.out.println("Generated an ECDSA keypair of type: " + privKey.getAlgorithm());
    System.out.println("The encoded public key is: " + HexFunctions.byte2hex(pubKey.getEncoded()));
	
    // Generate some random data to sign. //
    random = SecureRandom.getInstance("SHA1PRNG");
    System.out.println("Generating " + nBytes + " random bytes to sign.");
    byte[] plainText = new byte[nBytes];
    random.nextBytes(plainText);
    
    // Init sign
    signer = Signature.getInstance("Sha256withECDSA", "nCipherKM");
    signer.initSign(privKey);
	
	  // Signing of random data  //
    System.out.println("Signing the data.");
    signer.update(plainText);
    byte[] signature = signer.sign();
	
    Encoder b64 = Base64.getEncoder();
    String base64 = b64.encodeToString(signature);
			
    System.out.println( "Encoding Sign data." );
    System.out.println( "========================================================" );
    System.out.println(base64);	
    System.out.println( "========================================================" );

    // Verify the signature. //
    verifier = Signature.getInstance("Sha256withECDSA", "nCipherKM");
    System.out.print("Verifying the signature ... ");
    verifier.initVerify(pubKey);
    verifier.update(plainText);
    boolean succeeded = verifier.verify(signature);
    System.out.println((succeeded ? "succeeded." : "failed."));
	
    // Store the KeyStore. The store method saves the keys in the KeyStore
    // into the main nCipher security world.
    FileOutputStream out = new FileOutputStream("keystore.dat");
    ks.store(out, CARDSET_PASSPHRASE);
    out.close();
    System.out.println("Saved keys in keystore to Security World");
  }
  
  public static String toHex(byte[] data) {
	  StringBuilder sb = new StringBuilder();
	  for (byte b: data) sb.append(String.format("%02x", b&0xff));
	  return sb.toString();
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
