package com.csc.cscip.ux.common.security.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;

public class UXCLTTokenUtils {
	public static final String MAGIC_KEY = "obfuscate";
	public static String createToken(String username, long expires) {

		StringBuilder tokenBuilder = new StringBuilder();
		tokenBuilder.append(username);
		tokenBuilder.append("-");
		tokenBuilder.append(expires);
		tokenBuilder.append("-");
		tokenBuilder.append(UXCLTTokenUtils.computeSignature_PT(username, expires));
		return tokenBuilder.toString();
	}

	public static String computeSignature_PT(String username, long expires) {

		StringBuilder signatureBuilder = new StringBuilder();
		signatureBuilder.append(username);
		signatureBuilder.append("-");
		signatureBuilder.append(expires);
		signatureBuilder.append("-");
		signatureBuilder.append(UXCLTTokenUtils.MAGIC_KEY);
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("sha");
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("No sha algorithm available!");
		}
		return new String(Hex.encodeHexString(digest.digest(signatureBuilder.toString().getBytes())));
	}
}
