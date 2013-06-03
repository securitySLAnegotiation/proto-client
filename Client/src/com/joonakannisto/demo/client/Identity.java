package com.joonakannisto.demo.client;
// Create a certificate or a keypair if one does not exist yet

import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Date;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;


import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.ECKey.Curve;
import com.nimbusds.jose.jwk.Use;
import com.nimbusds.jose.util.Base64URL;


public class Identity {
	public static String keyfileName = "store2.key";
	public static String certfileName = "store2.cert";
	public static String commonName = "CN=Service Provider";
	public static X509Certificate ownCert() throws ClassNotFoundException, IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException, InvalidKeyException, IllegalStateException, SignatureException {
		try {
			InputStream file = new FileInputStream (certfileName);
			InputStream buffer = new BufferedInputStream(file);
			ObjectInput input = new ObjectInputStream(buffer);
			try {
				return (X509Certificate)input.readObject();
			}
			finally {
				input.close();
			}
		}
		catch (FileNotFoundException e) {
				Security.addProvider(new BouncyCastleProvider());
			    // yesterday
			    Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
			    // in 2 years
			    Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);
			    KeyPair keyPair = ownId();
			    
			    X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
			    X500Principal dnName = new X500Principal(commonName);
			    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
			    certGen.setSubjectDN(dnName);
			    certGen.setIssuerDN(dnName); // use the same
			    certGen.setNotBefore(validityBeginDate);
			    certGen.setNotAfter(validityEndDate);
			    certGen.setPublicKey(keyPair.getPublic());
			    certGen.setSignatureAlgorithm("SHA256withECDSA");
			    KeyPair myKeys= ownId();
			    PrivateKey priv = myKeys.getPrivate();
			    X509Certificate cert = certGen.generate(priv);
			    OutputStream file = new FileOutputStream( certfileName );
			    OutputStream buffer = new BufferedOutputStream( file );
			    ObjectOutput output = new ObjectOutputStream( buffer );
		        output.writeObject(cert);
		        output.close();
			    return cert;
		}
	}
	public static KeyPair ownId() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, ClassNotFoundException {
		// will fail if no key stored in file
		try {
			//use buffering
		      InputStream file = new FileInputStream( keyfileName );
		      InputStream buffer = new BufferedInputStream( file );
		      ObjectInput input = new ObjectInputStream ( buffer );
		        //deserialize the KeyPair
		      try{
		    	 return (KeyPair)input.readObject();
		      }       
		      finally {
		    	  input.close();
			}
		}

		catch (FileNotFoundException e) {
			
			//Security.addProvider(new BouncyCastleProvider());
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
			KeyPairGenerator g =KeyPairGenerator.getInstance("ECDSA");
			g.initialize(ecSpec, new SecureRandom());
			KeyPair pair =g.generateKeyPair();
			OutputStream file = new FileOutputStream( keyfileName );
		    OutputStream buffer = new BufferedOutputStream( file );
		    ObjectOutput output = new ObjectOutputStream( buffer );
		    output.writeObject(pair);
		    output.close();
		    return pair;
		    
		}
		
	}
//	public static ECKey jsonPubkey() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, ClassNotFoundException {
//		
//		// will fail if no key stored in file
//		try {
//			//use buffering
//			// not a good idea to handle public and private keys 
//			// in the same function when only public is needed
//		      InputStream file = new FileInputStream( keyfileName );
//		      InputStream buffer = new BufferedInputStream( file );
//		      ObjectInput input = new ObjectInputStream ( buffer );
//		        //deserialize the KeyPair
//		      try{
//		    	 KeyPair pair= (KeyPair)input.readObject();
//		    	 BCECPublicKey pub = (BCECPublicKey) pair.getPublic();
//		    	 java.security.spec.ECPoint w=pub.getW();
//		    	 ECKey jsonId = new ECKey(Curve.P_256, Base64URL.encode(w.getAffineX().toByteArray()), Base64URL.encode(w.getAffineY().toByteArray()), Use.SIGNATURE, , certfileName);
//		    	 return jsonId;
//		      }       
//		      finally {
//		    	  input.close();
//			}
//		}
//
//		catch (FileNotFoundException e) {
//			
//			Security.addProvider(new BouncyCastleProvider());
//			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
//			KeyPairGenerator g =KeyPairGenerator.getInstance("ECDSA", "BC");
//			g.initialize(ecSpec, new SecureRandom());
//			KeyPair pair =g.generateKeyPair();
//			 BCECPublicKey pub = (BCECPublicKey) pair.getPublic();
//	    	 java.security.spec.ECPoint w=pub.getW();
//	    	 ECKey jsonId = new com.nimbusds.jose.jwk.ECKey(Curve.P_256, Base64URL.encode(w.getAffineX().toByteArray()), Base64URL.encode(w.getAffineY().toByteArray()), Use.SIGNATURE,Algorithm.ECC,"1");
//			OutputStream file = new FileOutputStream( keyfileName );
//		    OutputStream buffer = new BufferedOutputStream( file );
//		    ObjectOutput output = new ObjectOutputStream( buffer );
//	        output.writeObject(pair);
//		    output.close();
//		    return jsonId;
//		    
//		}
//		
//	}
	public static String getThumbPrint(X509Certificate cert) 
		     throws NoSuchAlgorithmException, CertificateEncodingException {
		     MessageDigest md = MessageDigest.getInstance("SHA-1");
		     byte[] der = cert.getEncoded();
		     md.update(der);
		     byte[] digest = md.digest();
		     return hexify(digest);

		    }

  public static String hexify (byte bytes[]) {

		     char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', 
		       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

		     StringBuffer buf = new StringBuffer(bytes.length * 2);

		        for (int i = 0; i < bytes.length; ++i) {
		         buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
		            buf.append(hexDigits[bytes[i] & 0x0f]);
		        }

		        return buf.toString();
		    }

}