package com.joonakannisto.demo.client;


import org.json.JSONException;
import org.json.JSONObject;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;

public class Translate {
public static JSONObject capabilities(JSONObject SSLA) throws JSONException {
	String URI=Defaults.KBURI;
	try {
		JSONObject kbInfo = SSLA.getJSONObject("trustedKB");
		if (kbInfo.has("URI")) {
		URI =  kbInfo.getString("URI");
		
		}
		} catch (Exception e) {
		System.err.println("Cannot parse JSON");
		}

		ClientConfig config = new DefaultClientConfig();
	    Client client = Client.create(config);
		WebResource kbservice = client.resource(URI);
		JSONObject req = SSLA.getJSONObject("req");
		String response = kbservice.accept(Cli.APPLICATION_JWS_TYPE).post(String.class, req.toString());
		JSONObject cap = new JSONObject(response);
		return cap;
	}
}
