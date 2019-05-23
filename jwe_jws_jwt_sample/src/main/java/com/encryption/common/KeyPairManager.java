package com.encryption.common;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyPairManager {

	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return new KeyPair((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());

	}
}
