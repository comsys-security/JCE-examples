package EC.CA;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import com.ncipher.provider.km.nCipherKM;

import sun.misc.BASE64Encoder;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;


public class GenECDSA_SubCA {
	//TODO passphrase 
	private static char[] OCS_PASSPHRASE = "1234".toCharArray();
	private static String rootca_eckey_alias = "test_root_eckey";
	private static String attestca_key_alias = "test_attestca_eckey";
	private static String cert_filename = "attestca.crt";
	private static String SubCA_dn = "CN=Comsys Attestation CA, L=Suwon, C=KR, O=Comsys, OU=Security, ST=South Korea, emailAddress=jk.jo@pro-comsys.com";
	
	private static String plaintext = "test sign data";
	private static String sign_filename = "signature.txt";
	
	private static String prov_nCipherKM = "nCipherKM"; // HSM provider
	private static String KEY_STOREFILE = "keystore.dat";
	private static KeyStore ks = null;
	private static X509Certificate attestcaCert = null;
	private static Certificate rootca_cert = null;
	
	public static void main(String[] args) throws Exception {
		Security.addProvider(new nCipherKM());		
		//Security.addProvider(new BouncyCastleProvider());
		//TODO slot hash 
		//System.setProperty("protect", "module");
		
		// get rootCA_private key
		KeyPair rootCA_key = getKey(rootca_eckey_alias);
		
		// key pair
		KeyPair attestca_key = genkey(attestca_key_alias, rootCA_key);
		
		// sign
		sign(attestca_key);
		
		// save selfcert
		SaveCSR();
	}
	
	public static KeyPair getKey(String rootca_eckey_alias) throws Exception {
		
		ks = KeyStore.getInstance("nCipher.sworld", prov_nCipherKM);
		FileInputStream fKeyStore = new java.io.FileInputStream(KEY_STOREFILE);
		System.out.println("keyStore.load... ");
		ks.load(fKeyStore, OCS_PASSPHRASE);
		Key key = ks.getKey(rootca_eckey_alias, OCS_PASSPHRASE);
		rootca_cert = ks.getCertificate(rootca_eckey_alias);
		KeyPair root_CA_Key = new KeyPair(rootca_cert.getPublicKey(), (PrivateKey)key);
		fKeyStore.close();
		System.out.println("Key Info : " + key.toString() + key.getAlgorithm() + key.getFormat());
		return root_CA_Key;
	}

	public static KeyPair genkey(String alias, KeyPair rootCA_key) throws Exception {
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", prov_nCipherKM);
		ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp384r1");
		kpg.initialize(ecGenParameterSpec);
	    
	    KeyPair keyPair = kpg.generateKeyPair();
	    PrivateKey privateKey = keyPair.getPrivate();
	    PublicKey publicKey = keyPair.getPublic();

	    System.out.println("Generated an EDDSA keypair of type: " + privateKey.getAlgorithm());
	    System.out.println("The encoded public key is: " + toHexString(publicKey.getEncoded()));
		
	    attestcaCert = generateCertificate(publicKey, rootCA_key.getPrivate());
		//System.out.println("SelfCert : "+SelfCert);
		
		ks = KeyStore.getInstance("nCipher.sworld", prov_nCipherKM);
		
		//X509Certificate[] chain = new X509Certificate[1];
		Certificate[] certChain = new Certificate[] {rootca_cert, attestcaCert};
		
		System.out.println("attestca Cert : "+attestcaCert);
		attestcaCert.verify(rootCA_key.getPublic());
		
		FileInputStream fKeyStore = new java.io.FileInputStream(KEY_STOREFILE);
		ks.load(fKeyStore, OCS_PASSPHRASE);
		System.out.println("keyStore.setKeyEntry... ");
		
		// Add the public EC key to the keystore.
	    ks.setKeyEntry(alias, publicKey, OCS_PASSPHRASE , null);
	    System.out.println("Added ECDSAPublicKey to keystore");
	    
	    // Add the private EC key to the keystore.
		ks.setKeyEntry(alias, privateKey, OCS_PASSPHRASE , certChain);
		System.out.println("Added ECDSAPrivateKey to keystore");
		
		// Store the KeyStore. The store method saves the keys in the KeyStore
	    // into the main nCipher security world.
		FileOutputStream fos = new FileOutputStream(new File(KEY_STOREFILE));
		ks.store(fos, OCS_PASSPHRASE);
		System.out.println("Succeed Import KEY. ");
		fos.close();
		
		return keyPair;
	}
	
	public static void sign(KeyPair attestca_key) throws Exception {
		
	    Signature signer = Signature.getInstance("SHA256withECDSA", prov_nCipherKM);
	    signer.initSign(attestca_key.getPrivate());    
		    
		byte[] signature = null;
		    
		BASE64Encoder encoder = new BASE64Encoder();
		    
		// sign
		signer.update(plaintext.getBytes());
		signature = signer.sign();
		
		String base64 = encoder.encode(signature);
		System.out.println( "Encoding Sign data." );
		System.out.println( "========================================================" );
		System.out.println(base64);	
		System.out.println( "========================================================" );	
		
		    
		// init verify
		Signature verifying = Signature.getInstance("SHA256withECDSA", prov_nCipherKM);
		verifying.initVerify(attestca_key.getPublic());

		//verify
		verifying.update(plaintext.getBytes());
		boolean signatureOK = verifying.verify(signature);

		if(signatureOK)
			System.out.println("Success verification!");
		else
			System.out.println("Fail verification!");
		
		File f = new File(sign_filename);
        FileOutputStream fos_1 = new FileOutputStream(f);
        DataOutputStream dos = new DataOutputStream(fos_1);

        dos.writeBytes(base64);
        dos.flush();
        dos.close();
        System.out.println("save sign data...");	
		
	}
	
    public static void SaveCSR() throws CertificateEncodingException, IOException
    {
    	File f = new File(cert_filename);
        FileOutputStream fos_1 = new FileOutputStream(f);
        DataOutputStream dos = new DataOutputStream(fos_1);


        byte[] keyBytes = attestcaCert.getEncoded();
        BASE64Encoder b64=new BASE64Encoder();
        String  encoded = b64.encodeBuffer(keyBytes);

        encoded= "-----BEGIN CERTIFICATE-----\r\n" + encoded + "-----END CERTIFICATE-----";

        dos.writeBytes(encoded);
        dos.flush();
        dos.close();
        System.out.println("Cert.write...");	
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
			  int days = 7300;
			  String algorithm = "SHA384withECDSA";
			  PrivateKey privkey = signatureKey;
			  X509CertInfo info = new X509CertInfo();
			  Date from = new Date();
			  Date to = new Date(from.getTime() + days * 86400000l);
			  CertificateValidity interval = new CertificateValidity(from, to);
			  BigInteger sn = new BigInteger(64, new SecureRandom());
			  
			  X509Certificate cert1 = (X509Certificate) rootca_cert;
			  X500Name owner = new X500Name(SubCA_dn);
			  X500Name issuer = new X500Name(cert1.getIssuerDN().toString());
			  info.set(X509CertInfo.VALIDITY, interval);
			  info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
			  info.set(X509CertInfo.SUBJECT, owner);
			  info.set(X509CertInfo.ISSUER, issuer);   //root ca cert dn
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

