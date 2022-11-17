package EC.CA;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Base64.Encoder;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemReader;

import com.ncipher.provider.km.nCipherKM;



public class crtgenerator {
	public  static final String BEGIN_CERT     = "-----BEGIN CERTIFICATE-----";
    public  static final String END_CERT       = "-----END CERTIFICATE-----";
    public  static final int    CERT_LINE_LENGTH = 64;
    public  static final String BEGIN_CERT_REQ = "-----BEGIN CERTIFICATE REQUEST-----";
    public  static final String END_CERT_REQ   = "-----END CERTIFICATE REQUEST-----";
    public  static final int    CERT_REQ_LINE_LENGTH = 76;
    public  static final String CSRFile = "CA.csr";
	private static String keystorefile = "keystore.dat"; // path that import cert in keystore
	private static String cert_filename = "CA.crt"; //generate cert file.
	
	private static String alias = "Root ECDSA Key"; // 
	private static PrivateKey RootPrivateKey=null;
	private static char[] OCS_PASSPHRASE = "comsys2019".toCharArray();
	private static String prov_nCipherKM = "nCipherKM"; 
    
	public static PKCS10CertificationRequest getCSRFromPEM(String csrFile) throws IOException, CertificateException, SignatureException, NoSuchAlgorithmException {
	    	
			Security.addProvider(new BouncyCastleProvider());
			FileReader fileReader = new FileReader("CA.csr");
			PemReader pemReader = new PemReader(fileReader);

			PKCS10CertificationRequest csr = 
				new PKCS10CertificationRequest(pemReader.readPemObject().getContent());

			pemReader.close();
			fileReader.close();
			return csr;
	}    
    
	public static X509Certificate makeCertificate(PublicKey ca_pubKey, PrivateKey root_privateKey, PublicKey root_pubkey,
	X500Name owner, X500Name xname) throws OperatorCreationException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{

		BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
		Instant validFrom = Instant.now();
		Instant validUntil = validFrom.plus(10 * 360, ChronoUnit.DAYS);
		
		Security.addProvider(new BouncyCastleProvider());
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
			owner, serialNumber, Date.from(validFrom), Date.from(validUntil), xname, ca_pubKey);
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA").build(root_privateKey);
		X509CertificateHolder certHolder = builder.build(signer);
		X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
		System.out.println("Issuing Cert and verify...");	
		cert.verify(root_pubkey);
		return cert;
	}
	
	public static void main(String[] args) throws Exception{
		
		Security.addProvider(new nCipherKM());
		KeyPair keyPair;
		System.out.println("Read from CertificationRequest File :" + CSRFile);
		PKCS10CertificationRequest csr = getCSRFromPEM(CSRFile);
		X500Name xname = csr.getSubject();
		PublicKey CApublickey = KeyFactory.getInstance("ECDSA").generatePublic(new X509EncodedKeySpec(csr.getSubjectPublicKeyInfo().toASN1Primitive().getEncoded()));
		System.out.println("X500Name from CertificationRequest :" + xname);
		
		try{
			
			KeyStore ks = KeyStore.getInstance("ncipher.sworld",prov_nCipherKM);
			//FileInputStream fKeyStore = new FileInputStream(keystorefile);
			
			if(!new File(keystorefile).exists()) {
				System.out.println("No exist key store file.");

				ks.load(null, OCS_PASSPHRASE);
			}
			else {
				System.out.println("Exist key store file.");

				FileInputStream fKeyStore = new FileInputStream(keystorefile);
				ks.load(fKeyStore, OCS_PASSPHRASE);
			}			
			Key key = ks.getKey( alias, OCS_PASSPHRASE);	
			
			if ( key == null )
			{
				System.out.println( "The key " + alias + " doesn't exist in the keystore " + keystorefile );
				return;
			}

			if ( !(key instanceof PrivateKey) )
			{
				System.out.println( "The key " + alias + " is not a private key" );
				return;
			}
			
			X509Certificate rootcert = (X509Certificate) ks.getCertificate( alias );
			X500Name issuer = new X500Name( rootcert.getSubjectX500Principal().getName() );
			PublicKey root_publickey = rootcert.getPublicKey();
			keyPair = new KeyPair(rootcert.getPublicKey(), (PrivateKey)key);
	        RootPrivateKey = keyPair.getPrivate();
	        System.out.print( "Attempting to export the private key handle... \n" );
	  		
			X509Certificate CA_Cert = makeCertificate(CApublickey, RootPrivateKey, root_publickey, issuer, xname);
			System.out.println(CA_Cert);		
			
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = CA_Cert;
			
			/*if you need save ca_cert to HSM, you can use it. */			
			//ks.setKeyEntry(alias, privateKey, OCS_PASSPHRASE, chain);

			//FileOutputStream fos = new FileOutputStream(new File(keystorefile));
			//ks.store(fos, OCS_PASSPHRASE);
			//fos.close();
			
			File f = new File(cert_filename);
	        FileOutputStream fos_1 = new FileOutputStream(f);
	        DataOutputStream dos = new DataOutputStream(fos_1);


	        byte[] keyBytes = CA_Cert.getEncoded();
			Encoder b64 = Base64.getEncoder();
    		String encoded = b64.encodeToString(keyBytes);

	        encoded= "-----BEGIN CERTIFICATE-----\r\n" + encoded + "-----END CERTIFICATE-----";

	        dos.writeBytes(encoded);
	        dos.flush();
	        dos.close();
	        System.out.println("Save Issued Certificates.");		
			
		}
		catch(NoSuchAlgorithmException nsae){
			nsae.printStackTrace();
		}
		catch(CertificateException ce){
			ce.printStackTrace();
		}
		catch(InvalidKeyException ike){
			ike.printStackTrace();
		}
		catch(SignatureException se){
			se.printStackTrace();
		}
		catch(NoSuchProviderException nspre){
			nspre.printStackTrace();
		}
		catch(KeyStoreException kse){
			kse.printStackTrace();
		}
	}

	private static Provider nCipherKM() {
		return null;
	}
}
