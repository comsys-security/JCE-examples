package EC;

/**
 * ECDH Key Agreement example.
 *
 * <p>Demonstrates creation of ECDH key, ECDH key agreement handshake and encrypting/decryption of a
 * randomly generated message.
 */

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import com.ncipher.provider.km.nCipherKM;

class ECDHExample {

  int mKeySize = 521;
  int mMessageSize = 100;
  String mProvider = "nCipherKM";
  DateFormat mDateFormat = null;
  final int mAllowedKeySizes[] = {192, 224, 256, 384, 521};

  public ECDHExample() {
    mDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
  }

  private void trace(final String aMessage) {
    System.out.println(mDateFormat.format(new Date()) + "   " + aMessage);
  }

  /* Use the JCA classes to generate a new key */
  private KeyPair generateKey() throws NoSuchProviderException {
    trace("Generating the ECDH key.");

    KeyPairGenerator kpg = null;
    try {
      kpg = KeyPairGenerator.getInstance("ECDH", mProvider);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      errExit(e);
    }
    kpg.initialize(mKeySize);
    return kpg.generateKeyPair();
  }

  void run() throws GeneralSecurityException {
    byte[] message = new byte[mMessageSize];
    SecureRandom.getInstance("SHA1PRNG").nextBytes(message);
    /*
     * Phase 1. Alice and Bob generate they key material.
     */

    // Alice generates her key material
    trace("Alice gets an instance of key agreement class.");
    KeyAgreement aliceKeyAgreement = KeyAgreement.getInstance("ECDH", mProvider);
    trace("Alice obtains her key pair.");
    KeyPair aliceKeyPair = generateKey();

    // Bon generates his key material
    trace("Bob gets an instance of key agreement class.");
    KeyAgreement bobKeyAgreement = KeyAgreement.getInstance("ECDH", mProvider);
    trace("Bob obtains his key pair.");
    KeyPair bobKeyPair = generateKey();

    /*
     * Phase 2. Alice and Bob exchange their public keys. 
     */

    // Alice encodes her public key and sends it to Bob.
    trace("Alice encodes her key pair.");
    byte[] alicePubKeyEncoded = aliceKeyPair.getPublic().getEncoded();

    // Bob encodes his public key and sends it to Alice.
    trace("Bob encodes his key pair.");
    byte[] bobPubKeyEncoded = bobKeyPair.getPublic().getEncoded();

    /*
     * Phase 3. Alice and Bob generate the shared secret using the other party
     * public key.
     */

    // Alice uses Bob's public key for the phase stage of ECDH protocol.
    trace("Alice instantiate the ECDH Key Factory");
    KeyFactory aliceKeyFactory = KeyFactory.getInstance("ECDH", mProvider);
    X509EncodedKeySpec bobKeySpec = new X509EncodedKeySpec(bobPubKeyEncoded);
    trace("Alice generates a public key from Bob's key material.");
    PublicKey bobPubKey = aliceKeyFactory.generatePublic(bobKeySpec);
    trace("Alice initialises the Key agreement.");
    aliceKeyAgreement.init(aliceKeyPair.getPrivate());
    trace("Alice executes first phase....");
    aliceKeyAgreement.doPhase(bobPubKey, true);
    trace("Alice finished first phase....");

    // Bob uses Alices's public key for the phase stage of ECDH protocol.
    trace("Bob instantiate the ECDH Key Factory");
    KeyFactory bobKeyFactory = KeyFactory.getInstance("ECDH", mProvider);
    X509EncodedKeySpec aliceKeySpec = new X509EncodedKeySpec(alicePubKeyEncoded);
    trace("Bob generates a public key from Alice's key material.");
    PublicKey alicePubKey = bobKeyFactory.generatePublic(aliceKeySpec);
    trace("Bob initialises the Key agreement.");
    bobKeyAgreement.init(bobKeyPair.getPrivate());
    trace("Bob executes first phase....");
    bobKeyAgreement.doPhase(alicePubKey, true);
    trace("Bob finished first phase....");

    // Alice shared secret shall be identical with the Bob's shared secret.
    byte[] aliceSharedSecret = aliceKeyAgreement.generateSecret();
    byte[] bobSharedSecret = bobKeyAgreement.generateSecret();

    System.out.println("\nAlice's secret: " + toHexString(aliceSharedSecret));
    System.out.println("Bob's secret: " + toHexString(bobSharedSecret) + "\n");

    if (!Arrays.equals(aliceSharedSecret, bobSharedSecret)) {
      errExit("\t... differ !!!");
    }

    /*
     * Phase 4. Alice and Bob generate their secrets. They have to call
     * doPhase again because each generateSecret resets the agreement instance
     */

    // Alice generates her secret.
    trace("Alice doPhase() again.");
    aliceKeyAgreement.doPhase(bobKeyPair.getPublic(), true);
    trace("Alice generates her AES secret.");
    SecretKey aliceAesKey = aliceKeyAgreement.generateSecret("AES");

    // Bob generates his secret
    trace("Bob doPhase() again.");
    bobKeyAgreement.doPhase(aliceKeyPair.getPublic(), true);
    trace("Bobe generates her AES secret.");
    SecretKey bobAesKey = bobKeyAgreement.generateSecret("AES");

    /*
     * Phase 5. The parties communicates using a Cypher.
     */

    // Bob encrypts, using AES in ECB mode
    trace("Bob gets an instance of the AES/ECB/PKCS5Padding cipher.");
    Cipher bobCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

    trace("Bob initialises the cipher.");
    bobCipher.init(Cipher.ENCRYPT_MODE, bobAesKey);

    trace("Bob encrypts the message.");
    byte[] encyptedMessage = bobCipher.doFinal(message);

    // Alice decrypts the encrypted message received from Bob
    trace("Alice gets an instance of the AES/ECB/PKCS5Padding cipher.");
    Cipher aliceCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

    trace("Alice initialises the cipher.");
    aliceCipher.init(Cipher.DECRYPT_MODE, aliceAesKey);

    trace("Alice decryptes the encypted message.");
    byte[] decryptedMessage = aliceCipher.doFinal(encyptedMessage);
    trace("The message has been decrypted.");

    if (!Arrays.equals(message, decryptedMessage)) {
      System.out.println("Original message: " + toHexString(message));
      System.out.println("Recovered Message: " + toHexString(decryptedMessage));
      errExit("\t The messages differ !!!");
    }

    System.out.println(
        "\nSuccess! Correctly encrypted and decrypted message:\n" + toHexString(message));

    System.out.println("\nThe encrypted message:\n" + toHexString(encyptedMessage));
  }

  static void errExit(final String mess) {
    System.err.println(mess);
    System.exit(1);
  }

  static void errExit(final Exception e) {
    errExit(e.getClass().getName() + ": " + e.getMessage());
  }

  void errStop(final Exception e) {
    System.err.println(e.getClass().getName() + ": " + e.getMessage());
  }

  /*
   * Converts a byte array to hex string
   */
  private String toHexString(final byte[] aByteString) {
    return String.format("%x", new BigInteger(1, aByteString));
  }

  public static void main(final String args[]) {

    ECDHExample test = new ECDHExample();
    Security.addProvider(new nCipherKM());
    try {
      test.run();
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
      System.err.println(e);
      System.exit(1);
    }

    System.exit(0);
  }
}
