package com.encryption.jwt;

import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

import com.encryption.common.KeyPair;
import com.encryption.common.KeyPairManager;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class JWTValidation {

	public static void main(String[] args) throws NoSuchAlgorithmException, JOSEException, ParseException {
		KeyPair keyPair = KeyPairManager.generateKeyPair();
		String jwtToken = generateJWTToken(keyPair.getPrivateKey());
		validateJWTToken(keyPair.getRsaPublicKey(), jwtToken);

	}

	public static String generateJWTToken(RSAPrivateKey rsaPrivateKey) throws JOSEException {
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("subjectName").issuer("IssuerName")
				.expirationTime(new Date(new Date().getTime() + 60 * 1000)).build();
		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).contentType("text/plain").build();
		SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);

		signedJWT.sign(new RSASSASigner(rsaPrivateKey));
		return signedJWT.serialize();
	}

	public static void validateJWTToken(RSAPublicKey rsaPublicKey, String jwtToken)
			throws ParseException, JOSEException {
		SignedJWT signedJWT = SignedJWT.parse(jwtToken);
		JWSVerifier jwsVerifier = new RSASSAVerifier(rsaPublicKey);
		signedJWT.verify(jwsVerifier);

		System.out.println(signedJWT.getHeader());
		System.out.println(signedJWT.getJWTClaimsSet());
	}
}
