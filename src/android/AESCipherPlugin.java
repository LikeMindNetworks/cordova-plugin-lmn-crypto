package com.likemindnetworks.crypto;

import android.annotation.TargetApi;
import android.os.Build;
import android.util.Base64;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.io.ByteStreams;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipherPlugin extends CordovaPlugin {

	static {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
	}

	private final static String CIPHER_MODE = "AES/GCM/NoPadding";
	private final static int FILE_AES_IV_SIZE = 12;
	private final static int FILE_AES_TAG_SIZE = 16 * 8;

	private final static Cache<KeyDefinition, KeyParameter> pkcsCache
			= CacheBuilder.newBuilder().maximumSize(1000).build();

	private final static class KeyDefinition {
		final String key;
		final String salt;
		final int keySize;
		final int iteration;

		KeyDefinition(
				final String key,
				final String salt,
				final int keySize,
				final int iteration
		) {
			this.key = key;
			this.salt = salt;
			this.keySize = keySize;
			this.iteration = iteration;
		}
	}

	private final static SecureRandom secureRandom = new SecureRandom();

	private static byte[] getKey(
			final KeyDefinition keyDef
	) throws ExecutionException {
		return pkcsCache
			.get(
					keyDef,
					new Callable<KeyParameter>() {

						@Override
						public KeyParameter call() throws Exception {
							PKCS5S2ParametersGenerator generator
									= new PKCS5S2ParametersGenerator(
									new SHA256Digest()
							);

							generator.init(
									PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(
											keyDef.key.toCharArray()
									),
									Base64.decode(keyDef.salt, Base64.DEFAULT),
									keyDef.iteration
							);

							return (KeyParameter) generator
									.generateDerivedMacParameters(keyDef.keySize);
						}
					}
			)
			.getKey();
	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

	@Override
	public void initialize(CordovaInterface cordova, CordovaWebView webView) {
		super.initialize(cordova, webView);
	}

	public boolean execute(
			final String action,
			final JSONArray args,
			final CallbackContext callbackContext
	) throws JSONException {
		if (action.equals("decryptMessages")) {
			// 0th: key
			// 1st: array of json of cipher objects
			cordova.getThreadPool().execute(new Runnable() {
				@Override
				public void run() {
					PluginResult result = null;

					try {
						result = decryptMessages(
								args.getString(0), args.getString(1)
						);
					} catch (Exception e) {
						result = new PluginResult(
								PluginResult.Status.ERROR, e.getMessage()
						);
					} finally {
						if (result != null) {
							result.setKeepCallback(false);
						}

						callbackContext.sendPluginResult(result);
					}
				}
			});
		} else if (action.equals("encryptFile") || action.equals("decryptFile")) {
			// fin, fout, keyHex
			cordova.getThreadPool().execute(new Runnable() {
				@Override
				public void run() {
					PluginResult result = null;

					try {
						if (action.equals("encryptFile")) {
							result = encryptFile(
									args.getString(0),
									args.getString(1),
									args.getString(2)
							);
						} else {
							result = decryptFile(
									args.getString(0),
									args.getString(1),
									args.getString(2)
							);
						}
					} catch (Exception e) {
						result = new PluginResult(
								PluginResult.Status.ERROR, e.getMessage()
						);
					} finally {
						if (result != null) {
							result.setKeepCallback(false);
						}

						callbackContext.sendPluginResult(result);
					}
				}
			});
		} else {
			throw new JSONException("");
		}

		return true;
	}

	@TargetApi(Build.VERSION_CODES.KITKAT)
	private PluginResult decryptMessages(
			final String keyMapJSON, final String messagesJSON
	) throws
			JSONException,
			NoSuchAlgorithmException,
			InvalidKeySpecException,
			NoSuchPaddingException,
			InvalidKeyException,
			InvalidAlgorithmParameterException,
			BadPaddingException,
			IllegalBlockSizeException,
			UnsupportedEncodingException,
			ExecutionException
	{
		JSONArray messagesObjs = new JSONArray(messagesJSON);
		JSONObject keyMapObj = new JSONObject(keyMapJSON);
		JSONArray resMessagesObjs = new JSONArray();

		for (int i = 0; i < messagesObjs.length(); ++i) {
			JSONObject msgObj = messagesObjs.getJSONObject(i);

			if (
					!msgObj.has("type")
						|| !msgObj.getString("type").equals("text")
			) {
				// skip
				resMessagesObjs.put(i, msgObj);
				continue;
			}

			final JSONObject cipherObj = new JSONObject(
					msgObj.getString("content")
			);

			String keyVersion;

			if (msgObj.has("keyVersion")
					&& !msgObj.getString("keyVersion").equals("null")) {
				keyVersion = msgObj.getString("keyVersion");
			} else {
				keyVersion = "_default";
			}

			byte[] aesKey = getKey(new KeyDefinition(
					keyMapObj.getString(keyVersion),
					cipherObj.getString("salt"),
					cipherObj.getInt("ks"),
					cipherObj.getInt("iter")
			));

			Cipher aesCipher = Cipher.getInstance(CIPHER_MODE);
			SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");

			byte[] ivBytes = Base64.decode(
					cipherObj.getString("iv"), Base64.DEFAULT
			);
			byte[] ctBytes = Base64.decode(
					cipherObj.getString("ct"), Base64.DEFAULT
			);

			aesCipher.init(
					Cipher.DECRYPT_MODE,
					aesKeySpec,
					new GCMParameterSpec(cipherObj.getInt("ts"), ivBytes)
			);

			msgObj.put("content", new String(aesCipher.doFinal(ctBytes), "UTF-8"));

			resMessagesObjs.put(i, msgObj);
		}

		return new PluginResult(PluginResult.Status.OK, resMessagesObjs);
	}

	@TargetApi(Build.VERSION_CODES.KITKAT)
	private PluginResult encryptFile(
			final String finPath,
			final String foutPath,
			final String key
	) throws
			NoSuchPaddingException,
			NoSuchAlgorithmException,
			IOException,
			InvalidKeyException,
			InvalidParameterSpecException,
			InvalidAlgorithmParameterException
	{
		byte[] ivBytes = new byte[FILE_AES_IV_SIZE];
		secureRandom.nextBytes(ivBytes);

		Cipher aesCipher = Cipher.getInstance(CIPHER_MODE);
		aesCipher.init(
				Cipher.ENCRYPT_MODE,
				new SecretKeySpec(hexStringToByteArray(key), "AES"),
				new GCMParameterSpec(FILE_AES_TAG_SIZE, ivBytes)
		);

		final InputStream fin = new FileInputStream(finPath);
		final OutputStream fout = new FileOutputStream(foutPath);

		try {
			// write out iv to output file first
			fout.write(ByteBuffer.allocate(4).putInt(FILE_AES_TAG_SIZE).array());
			fout.write(ByteBuffer.allocate(4).putInt(FILE_AES_IV_SIZE).array());
			fout.write(ivBytes);

			ByteStreams.copy(fin, new CipherOutputStream(fout, aesCipher));
			fout.flush();
		} finally {
			fin.close();
			fout.close();
		}

		return new PluginResult(PluginResult.Status.NO_RESULT);
	}

	@TargetApi(Build.VERSION_CODES.KITKAT)
	private PluginResult decryptFile(
			final String finPath,
			final String foutPath,
			final String key
	) throws
			NoSuchPaddingException,
			NoSuchAlgorithmException,
			IOException,
			InvalidKeyException,
			InvalidParameterSpecException,
			InvalidAlgorithmParameterException
	{
		final InputStream fin = new FileInputStream(finPath);
		final OutputStream fout = new FileOutputStream(foutPath);

		try {
			int tagSize;
			int ivSize;
			byte[] intSizeBuf = new byte[4];

			// parse tag size
			fin.read(intSizeBuf);
			tagSize = ByteBuffer.wrap(intSizeBuf).getInt();

			// parse iv size
			fin.read(intSizeBuf);
			ivSize = ByteBuffer.wrap(intSizeBuf).getInt();

			// read iv
			byte[] ivBytes = new byte[ivSize];
			fin.read(ivBytes);

			Cipher aesCipher = Cipher.getInstance(CIPHER_MODE);
			aesCipher.init(
					Cipher.DECRYPT_MODE,
					new SecretKeySpec(hexStringToByteArray(key), "AES"),
					new GCMParameterSpec(tagSize, ivBytes)
			);

			ByteStreams.copy(new CipherInputStream(fin, aesCipher), fout);
			fout.flush();
		} finally {
			fin.close();
			fout.close();
		}

		return new PluginResult(PluginResult.Status.NO_RESULT);
	}

}
