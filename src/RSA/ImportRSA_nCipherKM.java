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
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.ncipher.provider.km.nCipherKM;
import sun.security.rsa.RSAPrivateCrtKeyImpl;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;


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
		System.setProperty("protect", "module");
		
		//TODO  privateKey file
		String privateKeyPath = "/home/comsys/work/JCE/RSA_ENCRYPT/src/test.pem";
		String publicKeyPath = "/home/comsys/work/JCE/RSA_ENCRYPT/src/test_pub.der";
		
		String alias = "importrsa2048tzlogsm8350_test_key";
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
	    try
	    {
	        sun.misc.BASE64Decoder decoder = new sun.misc.BASE64Decoder();
	        plainText = decoder.decodeBuffer(b64encoded);
	    }
	    catch (IOException ex)
	    {
        }
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

	public static X509Certificate generateCertificate(
			//X500Principal subjectDN,	 
			PublicKey pubKey,			 
			PrivateKey signatureKey		 
			//X509Certificate caCert,		 
			//CertType type
			)				
		throws NoSuchProviderException,NoSuchAlgorithmException,SignatureException,InvalidKeyException,IOException, CertificateException
		{
		String dn = "CN=Test, L=Seoul, C=KR";
		int days = 365;
		String algorithm = "SHA256withRSA";
		PrivateKey privkey = signatureKey;
		X509CertInfo info = new X509CertInfo();
		Date from = new Date();
		Date to = new Date(from.getTime() + days * 86400000l);
		CertificateValidity interval = new CertificateValidity(from, to);
		BigInteger sn = new BigInteger(64, new SecureRandom());
		X500Name owner = new X500Name(dn);
			 
		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
		info.set(X509CertInfo.SUBJECT, owner);
		info.set(X509CertInfo.ISSUER, owner);
		info.set(X509CertInfo.KEY, new CertificateX509Key(pubKey));
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
			 
		// Sign the cert to identify the algorithm that's used.
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(privkey, algorithm);
			 
		// Update the algorith, and resign.
		algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
		cert = new X509CertImpl(info);
		cert.sign(privkey, algorithm);
		return cert;
	}
}

