package com.joonakannisto.demo.client;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import com.nettgryppa.security.HashCash;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.ReadOnlyJWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64;

public class Cli {
	public final static String APPLICATION_JWS = "application/jws"; 
	public final static MediaType APPLICATION_JWS_TYPE = new MediaType("application","jws"); 
	//public final static int difficulty =12;
	public final static String idSP = "localhost";
	public final static int maxDifficulty =20;
	public static int expiration = 3600*24*30;
	public static void main(String[] args) throws UniformInterfaceException, ClientHandlerException, NoSuchAlgorithmException, CertificateException, JOSEException, JSONException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException, SignatureException, ClassNotFoundException, IOException {
		    ClientConfig config = new DefaultClientConfig();
		    Client client = Client.create(config);
		    WebResource service = client.resource(getBaseURI());
		    // Fluent interfaces
		    System.out.println("Requesting Negotiation parameters (This information should preferably come from trusted source)");
		    System.out.println(service.path("rest").path("negotiate").accept(APPLICATION_JWS).get(ClientResponse.class).toString());
		    // Get requirements
		    
		    String response = (service.path("rest").path("negotiate").accept(APPLICATION_JWS).get(String.class));
		    
		try {
			JWSObject jwsObject = JWSObject.parse(response);
			ReadOnlyJWSHeader header= jwsObject.getHeader();
			System.out.println("Header: "+header.toString());
			System.out.println("Signature: " +jwsObject.getSignature().toString());
			System.out.println("Payload: " +jwsObject.getPayload().toString());
			
			
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
			
			Base64 cert = header.getX509CertChain()[0];
			InputStream in = new ByteArrayInputStream(cert.decode());
			
			X509Certificate SP = (X509Certificate) certFactory.generateCertificate(in);
			PublicKey SPkey = SP.getPublicKey();
			if(SPkey.getAlgorithm().equalsIgnoreCase("EC")){
				org.bouncycastle.jce.interfaces.ECPublicKey ECSP = (org.bouncycastle.jce.interfaces.ECPublicKey) SPkey;
				ECPoint pointSP = ECSP.getQ();
				BigInteger x = pointSP.getX().toBigInteger();
				BigInteger y = pointSP.getY().toBigInteger();
				
				
				JWSVerifier verifier =new ECDSAVerifier(x, y);
				
				if (!jwsObject.verify(verifier)){
					System.out.println ("Signature is not verified. Abort.");
					return;
				}
	            System.out.println("Signature verified");
	            System.out.println("Ready to craft a SSLA proposal");
	            System.in.read();

				Payload payload=jwsObject.getPayload();
				JSONObject parameters = new JSONObject(payload.toString());
				int difficulty = 12;
				String puzzlename="hashcash";
				if (parameters.has(puzzlename)){
						JSONObject puzzle = new JSONObject(parameters.get("hashcash").toString());
						difficulty = puzzle.getInt("zeroes");
						if (difficulty > maxDifficulty) {
							System.out.println ("The server is asking too difficult stamps. Abort.");
							return;
						}
				}

				
			String thumbSP=Identity.getThumbPrint(SP);
			System.out.println("Making SSLA proposal for SP "+thumbSP);
			JSONObject idSP =  new JSONObject().put("x5t",thumbSP);
			String propose = userSSLAProposal(idSP);
			String proposeSigned = Sign.signedJWT(new Payload (propose));
			
			System.out.println("User proposal: "+ propose);
			System.in.read();
			System.out.println("Sending as signed JWS");
			
			String resource = resourceURI(thumbSP, difficulty);
			response = (service.path("rest").path("negotiate").path(resource).type(APPLICATION_JWS_TYPE).put(String.class, proposeSigned).toString());
			try {
				JWSObject jwsResponse = JWSObject.parse(response);
				System.out.println("Received a response");
				System.out.println("SP response: " +jwsResponse.getPayload());
				// We can use the same verifier here
				if (jwsResponse.verify(verifier)){
					System.out.println("Signature correct") ;
				}
				else {
					System.out.println("Signature does not match");
				}
				
				JSONObject received = new JSONObject(jwsResponse.getPayload().toString());
				received.remove("jti");				
				String sent = propose;
				if (Match.equalJSONObject(sent, received.toString())) {
					System.out.println("Sent and received are equal");
					System.out.println("SSLA Finished");
					System.out.println(response);
				}
				else {
					System.out.println("Reply payload is different from sent. We should validate it with KB, but lets accept it for demo purposes");
				}
			
				String confirm = Sign.signedJWT(jwsResponse.getPayload());
				System.out.println("Sending: "+ JWSObject.parse(confirm).getPayload().toString());
				// If the proposed SSLA is simple to confirm
				if (jwsResponse.getPayload().toJSONObject().containsKey("commit")) {
					System.out.println("");
					System.out.println("For this demo we have a confirmation message example");
					System.out.println("There is a commit value in the SSLA, and the server will return the seed value against a signed SSLA from the client");
					System.out.println("This seed value acts as a confirmation that the negotiation has been completed");
					String token = service.path("rest").path("negotiate").path(resource).type(MediaType.TEXT_PLAIN).post(String.class, confirm).toString();
					System.out.println("Return token " +token);
					System.out.println("Return token sha1: "+ DigestUtils.sha1Hex(token));
					System.out.println("Committed value: "+ jwsResponse.getPayload().toJSONObject().get("commit"));
					
				}
				System.in.read();
				// We have probably used the resource URI already
				resource = resourceURI(thumbSP, difficulty);
				response = (service.path("rest").path("negotiate").path(resource).type(APPLICATION_JWS_TYPE).put(String.class, confirm).toString());
				sent = jwsResponse.getPayload().toString();
				try {
					jwsResponse = JWSObject.parse(response);	
					System.out.println("SP response: " +jwsResponse.getPayload().toString());
					// We can use the same verifier here
					if (jwsResponse.verify(verifier)){
						System.out.println("Signature valid") ;
					}
					else {
						System.out.println("Signature invalid. Abort.");
						return;
					}
					received = new JSONObject(jwsResponse.getPayload().toString());
					System.out.println("Payload: "+received.toString());
					received.remove("jti");	
					//System.out.println(received.toString());
					JSONObject sentJ = new JSONObject(sent);
					sentJ.remove("jti");
					String sentnojti = sentJ.toString();
					if (Match.equalJSONObject(sentnojti, received.toString())) {
						System.out.println("Sent and received JSONObjects are equal");
						System.out.println("SSLA: "+sent);
						System.in.read();
						System.out.println("Signed SSLA SP (JWS): "+response);
						System.out.println("");
						System.out.println("Signed SSLA User (JWS): " +confirm );
					}
					else {
						System.out.println("Reply different from sent.");
						System.out.println("Sent: "+sentnojti);
						System.out.println("Received: "+received.toString());
					}
				} catch (Exception e) {
					System.out.println("Unexpected response"+e.getMessage()+response);
				}
			} catch (Exception e) {
				System.err.println("Could not parse response jws"+ e.getMessage());
			}
			
			
//			System.out.println(JWSObject.parse(response).getPayload());
			}
			else {
				System.out.println ("Only EC keys implemented at this point");
				return;
			}
        } catch (ParseException e) {
        
                System.err.println("Couldn't parse JWS object: " + e.getMessage());
                return;
        }
		   
	  }
	public static String resourceURI(String idSP,int difficulty) throws NoSuchAlgorithmException {
		HashCash stamp = HashCash.mintCash(idSP, difficulty);
		return stamp.toString();
	}
	private static URI getBaseURI() {
	    return UriBuilder.fromUri("http://localhost:8080/fi.joonakannisto.jersey.first").build();
	  }
	public static String userSSLAProposal(JSONObject idSP) throws JSONException, CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException, SignatureException, ClassNotFoundException, IOException {
		JSONObject SSLA= new JSONObject().put("idU", new JSONObject().put("x5t", Identity.getThumbPrint(Identity.ownCert())));
		SSLA.put("idSP", idSP);
		long time = System.currentTimeMillis() /1000L;
		int now =((int)time);
		SSLA.put("exp", now+expiration);
		SSLA.put("nbf", now);
		SSLA.put("nid",Sign.randomHex(32));
		
		JSONArray requirements = new JSONArray().put("id1");
		requirements.put("id2");
		requirements.put("id3");
		requirements.put("id4");
		SSLA.put("req", requirements);
		JSONArray id2capabilities = new JSONArray().put("mechanism1").put("mechanism2").put("mechanism3");
		JSONArray capabilities = new JSONArray().put(new JSONObject().put("id2", id2capabilities));
		SSLA.put("cap", capabilities);
		SSLA.put("trustedKB", trustedKB());
		return SSLA.toString();
	}
	public static JSONObject trustedKB() throws CertificateEncodingException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalStateException, SignatureException, JSONException, ClassNotFoundException, IOException {
		JSONObject idKB = new JSONObject().put("idKB", new JSONObject().put("x5t", Identity.getThumbPrint(Identity.ownCert())));
		JSONObject trustedKB = new JSONObject().put("URI", "http://userkb.domain/idU/idSP/token");
		trustedKB.put("idKB", idKB);
		return trustedKB;
	}
	} 
	

