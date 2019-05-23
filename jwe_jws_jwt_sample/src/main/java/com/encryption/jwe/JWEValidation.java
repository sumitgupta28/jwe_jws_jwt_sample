package com.encryption.jwe;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.lang.JoseException;

import com.encryption.common.CommonConstants;

public class JWEValidation {

	public String encrypt(String messageToEncrypt, RSAPublicKey rsaPublicKey) throws JoseException {
		JsonWebEncryption jsonWebEncryption = new JsonWebEncryption();

		jsonWebEncryption.setAlgorithmHeaderValue(CommonConstants.JWE_KEY_ENC_ALGO);
		jsonWebEncryption.setEncryptionMethodHeaderParameter(CommonConstants.JWE_CONTENT_ENC_ALGO);
		jsonWebEncryption.setPlaintext(messageToEncrypt);
		jsonWebEncryption.setKey(rsaPublicKey);

		return jsonWebEncryption.getCompactSerialization();
	}

	public String decrypt(String messageToDecrypt, RSAPrivateKey rsaPrivateKey) throws JoseException {
		JsonWebEncryption jsonWebEncryption = new JsonWebEncryption();
		jsonWebEncryption.setAlgorithmConstraints(new AlgorithmConstraints(
				AlgorithmConstraints.ConstraintType.WHITELIST, new String[] { CommonConstants.JWE_KEY_ENC_ALGO }));
		jsonWebEncryption.setContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(
				AlgorithmConstraints.ConstraintType.WHITELIST, new String[] { CommonConstants.JWE_CONTENT_ENC_ALGO }));

		jsonWebEncryption.setKey(rsaPrivateKey);

		jsonWebEncryption.setCompactSerialization(messageToDecrypt);
		return jsonWebEncryption.getPlaintextString();

	}
}
