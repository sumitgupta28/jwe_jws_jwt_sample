package com.encryption.common;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyPair {

	private RSAPublicKey rsaPublicKey;
	private RSAPrivateKey privateKey;

	public KeyPair(RSAPublicKey rsaPublicKey, RSAPrivateKey privateKey) {

		this.rsaPublicKey = rsaPublicKey;
		this.privateKey = privateKey;
	}

	public RSAPublicKey getRsaPublicKey() {
		return rsaPublicKey;
	}

	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}

}
