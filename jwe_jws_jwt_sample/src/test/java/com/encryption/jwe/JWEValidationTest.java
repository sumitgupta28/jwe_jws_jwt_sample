package com.encryption.jwe;

import java.security.NoSuchAlgorithmException;

import org.jose4j.lang.JoseException;
import org.junit.Test;

import com.encryption.common.KeyPair;
import com.encryption.common.KeyPairManager;

import net.minidev.json.JSONObject;

public class JWEValidationTest {

	@Test
	public void testEncrypt() throws NoSuchAlgorithmException, JoseException {
		KeyPair keyPair = KeyPairManager.generateKeyPair();
		JWEValidation jweValidation = new JWEValidation();
		String encryptedContent = jweValidation.encrypt(getJsonContent(), keyPair.getRsaPublicKey());
		org.junit.Assert.assertNotNull(encryptedContent);
	}

	@Test
	public void testDecrypt() throws NoSuchAlgorithmException, JoseException {
		KeyPair keyPair = KeyPairManager.generateKeyPair();
		JWEValidation jweValidation = new JWEValidation();
		String encryptedContent = jweValidation.encrypt(getJsonContent(), keyPair.getRsaPublicKey());
		org.junit.Assert.assertNotNull(encryptedContent);
		String plainText = jweValidation.decrypt(encryptedContent, keyPair.getPrivateKey());
		org.junit.Assert.assertEquals(plainText, getJsonContent());
	}

	public static String getJsonContent() {
		JSONObject jsonObject = new JSONObject();
		jsonObject.put("userId", "exampleUserId");
		jsonObject.put("userEmail", "exmpleusermail@mail.com");
		return jsonObject.toJSONString();
	}

}
