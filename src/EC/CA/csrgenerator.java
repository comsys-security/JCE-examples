package EC.CA;
import com.ncipher.jutils.HexFunctions;
import com.ncipher.provider.km.nCipherKM;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;

class csrgenerator {

        public static void main(String[] args) throws GeneralSecurityException, IOException, OperatorCreationException {
		
		char[] CARDSET_PASSPHRASE = "comsys2019".toCharArray();
		String keyalias = "Root ECDSA Key";
		String cakeyalias = "CA ECDSA Key";
		String save_csr_filename = "CA.csr";

		Security.addProvider(new nCipherKM());
		
		// Create a cardset protected keystore.
        //System.setProperty("protect", "softcard:284141b6fc9843613c68bf97b3bb8e8cf1f6a102");
        System.out.println("Sample Java Application");
        System.out.println("nShield JCE");
        System.out.println("for testing only");

        // define variable for nShield JCE
        String provider = "nCipherKM";
        String algorithm = "ECDSA";
        int keyLength;
        keyLength = 2048;

        // generate Root ECDSA key
        System.out.println("Generate Root ECDSA key...");
        KeyPairGenerator keyPairGen = null;
        try {
                 keyPairGen = KeyPairGenerator.getInstance(algorithm, provider);
                 //keyPairGen = KeyPairGenerator.getInstance(algorithm);
        } catch (Exception e) {
                System.err.println(e.getClass().getName()+":"+e.getMessage());
				System.exit(1);
        }
         // Generate an ECDSA keypair
		ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");  //secp256r1 curve
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "nCipherKM");
		kpg.initialize(ecSpec);
	
		KeyPair root_keyPair = kpg.generateKeyPair();
		PrivateKey root_privKey = root_keyPair.getPrivate();
		PublicKey root_pubKey = root_keyPair.getPublic();
		System.out.println("Generated an Root ECDSA keypair of type: " + root_privKey.getAlgorithm());
		System.out.println("The encoded root public key is: " + HexFunctions.byte2hex(root_pubKey.getEncoded()));
		
		KeyStore ks = KeyStore.getInstance("ncipher.sworld", "nCipherKM");
		ks.load(null, CARDSET_PASSPHRASE);
		System.out.println("Created keystore");

		// Add the public ECDSA key to the keystore.
		ks.setKeyEntry(keyalias , root_pubKey, CARDSET_PASSPHRASE, null);

		// Generate an ECDSA Key pair for the certificate
		final Certificate certificate = makeCertificate(root_keyPair, "nCipherKM");
		Certificate[] certChain = new Certificate[] {certificate};

		// Add the private ECDSA key to the keystore.
		ks.setKeyEntry(keyalias, root_privKey, CARDSET_PASSPHRASE, certChain);
		System.out.println("Added Root ECDSAPrivateKey to keystore");

		// Store the KeyStore. The store method saves the keys in the KeyStore
		// into the main nCipher security world.
		FileOutputStream out = new FileOutputStream("keystore.dat");

		// CA Key generate and creat Certificate Signing Request
		System.out.println("Generated an CA ECDSA keypair of type: " + root_privKey.getAlgorithm());
		KeyPair CA_ECDSAKeyPair = kpg.generateKeyPair();
		PrivateKey ca_privKey = CA_ECDSAKeyPair.getPrivate();
		final Certificate ca_dummycertificate = makeCertificate(CA_ECDSAKeyPair, "nCipherKM");
		Certificate[] certChain_dummy = new Certificate[] {ca_dummycertificate};
		ks.setKeyEntry(cakeyalias, ca_privKey, CARDSET_PASSPHRASE, certChain_dummy);
		System.out.println("Added CA ECDSAPrivateKey to keystore");
		byte[] csr = make_csr(CA_ECDSAKeyPair, provider);

		ks.store(out, CARDSET_PASSPHRASE);
		out.close();
		System.out.println("Saved keys in keystore to Security World");

		SaveCSR(save_csr_filename, csr);
		System.out.println("Saved CA CERTIFICATE SIGNING REQUEST File : "+ save_csr_filename);
        }
		
		/** This function generates a new Certificate Signing Request. 
		 * @throws IOException
		 * @throws OperatorCreationException */
	  
		static byte[] make_csr(final KeyPair KeyPair, final String aProviderName) throws IOException, OperatorCreationException {
			
			Security.addProvider(new BouncyCastleProvider());

			X500Principal principal = new X500Principal ("CN=CA Comsys, C=Korea, ST=comsys, L=comsys, O=comsys, OU=comsys, EMAILADDRESS=jk.jo@pro-comsys.com");
			PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(principal, KeyPair.getPublic());
			
			JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
			ContentSigner signer = csBuilder.build(KeyPair.getPrivate());
			PKCS10CertificationRequest csr = p10Builder.build(signer);
    	return csr.getEncoded();
	  	}

	  	public static void SaveCSR(String filename , byte[] csr)
		{
		
			PemObject pemObject = new PemObject("CERTIFICATE SIGNING REQUEST", csr);
			StringWriter str = new StringWriter();
			PEMWriter pemWriter = new PEMWriter(str);
			
			try {
				pemWriter=new PEMWriter(new FileWriter(filename));
				pemWriter.writeObject(pemObject);
				pemWriter.close();
				str.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}		
		}
		static Certificate makeCertificate(final KeyPair KeyPair, final String ProviderName) throws CertificateException, CertIOException, OperatorCreationException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
			 
			BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
			Instant validFrom = Instant.now();
			Instant validUntil = validFrom.plus(10 * 360, ChronoUnit.DAYS);
			
			Security.addProvider(new BouncyCastleProvider());
			String principal ="CN=Root Comsys, C=Korea, ST=comsys, L=comsys, O=comsys, OU=comsys, EMAILADDRESS=jk.jo@pro-comsys.com";
			X500Name owner = new X500Name(principal);
			X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
				owner, serialNumber, Date.from(validFrom), Date.from(validUntil), owner, KeyPair.getPublic());
			ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA").build(KeyPair.getPrivate());
			X509CertificateHolder certHolder = builder.build(signer);
			X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
			cert.verify(KeyPair.getPublic());
			return cert;
		}
}
