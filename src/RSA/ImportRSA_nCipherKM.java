package RSA;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Base64.Decoder;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import com.ncipher.provider.km.nCipherKM;


public class ImportRSA_nCipherKM {
	//TODO passphrase 
	//private static char[] OCS_PASSPHRASE = "comsys2019".toCharArray();

	//nShield HSM module protect login

	private static String prov_nCipherKM = "nCipherKM"; // HSM provider
	private static String prov_BC = "BC"; // BC provider
	private static String KEY_STOREFILE = "keystore.dat";
	//private static String KEY_STOREFILE_bc = "keystore_bc.dat";
	private static KeyStore ks = null;
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new nCipherKM());		
		//TODO slot hash 
		//System.setProperty("protect", "module");
		
		//TODO  privateKey file
		String privateKeyPath = "test.pem";
		String publicKeyPath = "test_pub.der";
		
		String alias = "Import_Key";
		System.out.println(alias);
		
		// key pair
		storePair(privateKeyPath,publicKeyPath, alias);
		
		// private key
		getKey(alias);
	}

	public static void storePair(String privateKeyPath,String publicKeyPath, String alias) throws Exception {

		File privateKeyFile = new File(privateKeyPath);
		FileInputStream privateKeyIs;
		privateKeyIs = new FileInputStream(privateKeyFile);
		DataInputStream dis = new DataInputStream(privateKeyIs);
		byte[] privatekeyBytes = new byte[(int) privateKeyFile.length()];
		dis.readFully(privatekeyBytes);
		dis.close();
		privateKeyIs.close();

		String privKeyPEM = new String(privatekeyBytes).replace("-----BEGIN RSA PRIVATE KEY-----", "")
				.replace("-----END RSA PRIVATE KEY-----", "").replace("\n", "").replace("\r", "");

		byte[] privateKeyDecode = b64Decode(new String(privKeyPEM));
		byte[] pubkeyBytes = Files.readAllBytes(Paths.get(publicKeyPath));
		
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKeyDecode);
		X509EncodedKeySpec x509spec = new X509EncodedKeySpec(pubkeyBytes);
		//RSAPrivateKey
		KeyFactory keyFactory = KeyFactory.getInstance("RSA",prov_BC);
		RSAPrivateKey privateKey = (RSAPrivateCrtKey)keyFactory.generatePrivate(spec);
		
		//create a KeySpec and let the Factory due the Rest. You could also create the KeyImpl by your own.
		//PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(privateKey.getModulus(), privateKey.));
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(x509spec);
		System.out.println(publicKey); //store it - that's it
		
		X509Certificate SelfCert = generateCertificate(publicKey, privateKey);
		//System.out.println("SelfCert : "+SelfCert);
		
		ks = KeyStore.getInstance("nCipher.sworld", prov_nCipherKM);
		
		//X509Certificate[] chain = new X509Certificate[1];
		Certificate[] certChain = new Certificate[] {SelfCert};
		
		System.out.println("SelfCert : "+SelfCert);
		SelfCert.verify(publicKey);
		
		ks.load(null, null);
		System.out.println("keyStore.setKeyEntry... ");
		
		// Add the public RSA key to the keystore.
	    ks.setKeyEntry(alias, publicKey, null, null);
	    System.out.println("Added RSAPublicKey to keystore");
	    
	    // Add the private RSA key to the keystore.
		ks.setKeyEntry(alias, privateKey, null, certChain);
		System.out.println("Added RSAPrivateKey to keystore");
		
		// Store the KeyStore. The store method saves the keys in the KeyStore
	    // into the main nCipher security world.
		FileOutputStream fos = new FileOutputStream(new File(KEY_STOREFILE));
		ks.store(fos,null);
		System.out.println("Succeed Import KEY. ");
		fos.close();
	}
	
	public static void getKey(String alias) throws Exception {
		
		ks = KeyStore.getInstance("nCipher.sworld", prov_nCipherKM);
		FileInputStream fKeyStore = new java.io.FileInputStream(KEY_STOREFILE);
		ks.load(fKeyStore, null);
		Key key = ks.getKey(alias, null);
		fKeyStore.close();
		System.out.println("Key Info : " + key.toString() + key.getAlgorithm() + key.getFormat());
	}
	public static byte[] b64Decode(String b64encoded)
	{
	    byte[] plainText = null;
	    Decoder decoder = Base64.getDecoder();
		plainText = decoder.decode(b64encoded);
        return plainText;
	}
	public static String toHexString(byte[] block) {
		StringBuffer buf = new StringBuffer();
		char[] hexChars = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			               'A', 'B', 'C', 'D', 'E', 'F' };
		int len = block.length;
		int high = 0;
		int low = 0;
			
		for (int i = 0; i < len; i++) {
			high = ((block[i] & 0xf0) >> 4);
			low = (block[i] & 0x0f);
			buf.append(hexChars[high]);
			buf.append(hexChars[low]);
		}

		return buf.toString();
	}

	public static X509Certificate generateCertificate(PublicKey publickey , PrivateKey privateKey) 
	throws NoSuchProviderException,NoSuchAlgorithmException,SignatureException,InvalidKeyException,IOException, CertificateException, OperatorCreationException
		{
			BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
			Instant validFrom = Instant.now();
			Instant validUntil = validFrom.plus(10 * 360, ChronoUnit.DAYS);
			
			Security.addProvider(new BouncyCastleProvider());
			String principal ="CN=Self Comsys, C=Korea, ST=comsys, L=comsys, O=comsys, OU=comsys, EMAILADDRESS=jk.jo@pro-comsys.com";
			X500Name owner = new X500Name(principal);
			X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				owner, serialNumber, Date.from(validFrom), Date.from(validUntil), owner, publickey);
			ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
			X509CertificateHolder certHolder = builder.build(signer);
			X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
			cert.verify(publickey);
			return cert;
	}
}

