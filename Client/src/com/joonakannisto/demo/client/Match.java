package com.joonakannisto.demo.client;

import java.util.ArrayList;
import java.util.Iterator;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class Match {
	public static Boolean subset(JSONArray bigger, JSONArray smaller) throws JSONException {
		ArrayList<String> user = new ArrayList<String>();
		ArrayList<String> splist = new ArrayList<String>();
		if (bigger != null && smaller != null) {
			for (int j = 0; j < bigger.length(); j++) {
				user.add(bigger.getString(j));
			}
			for (int j = 0; j < smaller.length(); j++) {
				splist.add(smaller.getString(j));
			}
			return splist.containsAll(user);
		}
		else {
			return false;
		}
	}
	public static Boolean equalArray (String as, String bs) throws JSONException {
		
		try {
			JSONArray a = new JSONArray(as);
			JSONArray b = new JSONArray(bs);
			ArrayList<String> user = new ArrayList<String>();
			ArrayList<String> splist = new ArrayList<String>();
			if (a != null && b != null) {
				for (int j = 0; j < a.length(); j++) {
					user.add(a.getString(j));
				}
				for (int j = 0; j < b.length(); j++) {
					splist.add(b.getString(j));
				}
				return (user.containsAll(splist) && splist.containsAll(user));
			}
			else {
				// Make two null arrays equal
				return (a == null && b == null);
			}	
		} catch (JSONException e) {
			return false;
		}
		
	}
	// I wonder why no one has made this in the lib
	// My implementation probably horribly inefficient
	public static Boolean equalJSONObject (String a, String b) {
		try {
			JSONObject aJ = new JSONObject(a);
			JSONObject bJ = new JSONObject(b);
			if (aJ != null && bJ !=null) {
			for (Iterator<?> keys = aJ.keys(); keys.hasNext();) {
				String key = (String) keys.next();
				if (bJ.has(key)) {
					if (!equalJSONObject(bJ.get(key).toString(),aJ.get(key).toString()) 
							&&!equalArray(aJ.getString(key).toString(), bJ.get(key).toString())&&
							!aJ.get(key).toString().equals(bJ.get(key).toString())){
						return false;
					}
				}
				else {
					return false;	
				}
			}
			return true;
			}
			else {
				return (aJ == null && bJ == null);
			}
		}	
		catch (JSONException e) {
			return false;
		}
	}
	public static Boolean containsOneOrMore(JSONArray bigger, JSONArray smaller) throws JSONException {
		ArrayList<String> user = new ArrayList<String>();
		if (bigger != null && smaller != null) {
			for (int j = 0; j < bigger.length(); j++) {
				user.add(bigger.getString(j));
			}
			for (int j = 0; j < smaller.length(); j++) {
				if (user.contains(smaller.getString(j))){
					return true;
				}
			}
			// no hit in the loop
			return false;
			
		}
		else {
			return false;
		}
	}
}
