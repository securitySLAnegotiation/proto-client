package com.joonakannisto.demo.client;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECPrivateKey;

import org.apache.commons.codec.binary.Hex;
import com.nimbusds.jose.Payload;
import org.json.*;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;


public class Sign {
	public static Boolean debug = true;
public static String signedJWT (com.nimbusds.jose.Payload payload) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, ClassNotFoundException, CertificateEncodingException, InvalidKeyException, IllegalStateException, SignatureException, JSONException {
			JWSHeader header = new JWSHeader(JWSAlgorithm.ES256);
			header.setContentType("text/plain");
			Base64[] chain = new Base64[1];
			chain[0] = new Base64((String)Base64.encode(Identity.ownCert().getEncoded()).toString());
			
			header.setX509CertChain(chain);
			
			
			JSONObject contract = new JSONObject(payload.toString());
			KeyPair pair =Identity.ownId();
			ECPrivateKey priv= (ECPrivateKey) pair.getPrivate();
			contract.put("jti",randomHex(32));
			payload = new Payload(contract.toString());
			JWSObject jwsObject = new JWSObject(header, payload);

			// Create ECDSA signature
			JWSSigner signer = new ECDSASigner(priv.getS());
			
			try {
				jwsObject.sign(signer);
				
				return jwsObject.serialize();
				
			} catch (JOSEException e) {
				System.err.println("Couldn't sign JWS object: " + e.getMessage());
				return "";
			}
}
public static String randomHex(int bytes) {
	byte[] random = new byte[bytes];
	SecureRandom sr1 = new SecureRandom();
	sr1.nextBytes(random);
	return new String (Hex.encodeHex(random));
}
}
