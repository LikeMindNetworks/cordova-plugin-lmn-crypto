package com.likemindnetworks.crypto;

import android.annotation.TargetApi;
import android.os.Build;
import android.util.Base64;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

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

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipherPlugin extends CordovaPlugin {

	static {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
	}

	private final static Cache<String, KeyParameter> pkcsCache = CacheBuilder
			.newBuilder()
			.maximumSize(1000)
			.build();

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
					} catch (GeneralSecurityException e) {
						result = new PluginResult(
								PluginResult.Status.ERROR, e.getMessage()
						);
					} catch (UnsupportedEncodingException e) {
						result = new PluginResult(
								PluginResult.Status.ERROR, e.getMessage()
						);
					} catch (JSONException e) {
						result = new PluginResult(
								PluginResult.Status.ERROR, e.getMessage()
						);
					} catch (ExecutionException e) {
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
		} else if (action.equals("encryptFile")) {
			// 0th: input file path
			// 1st: output file path
			// 2nd: key
			// 3rd: iv
			// 4th: tagSize
//			final String fin = args.getString(0);
//			final String fout = args.getString(1);
//			final String keyBase64= args.getString(2);
//			final String ivBase64 = args.getString(3);
//			final int tagSize = Integer.valueOf(args.getString(4));
			throw new JSONException("");
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

			final String salt = cipherObj.getString("salt");
			byte[] ivBytes = Base64.decode(
					cipherObj.getString("iv"), Base64.DEFAULT
			);
			byte[] ctBytes = Base64.decode(
					cipherObj.getString("ct"), Base64.DEFAULT
			);

			String keyVersion;

			if (msgObj.has("keyVersion")
					&& !msgObj.getString("keyVersion").equals("null")) {
				keyVersion = msgObj.getString("keyVersion");
			} else {
				keyVersion = "_default";
			}

			final String key = keyMapObj.getString(keyVersion);
			final int iter = cipherObj.getInt("iter");
			final String cacheKey = key + iter + salt;

			KeyParameter keyParameter = pkcsCache.get(
				cacheKey,
				new Callable<KeyParameter>() {

					@Override
					public KeyParameter call() throws Exception {
						PKCS5S2ParametersGenerator generator
								= new PKCS5S2ParametersGenerator(
									new SHA256Digest()
								);

						generator.init(
							PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(
									key.toCharArray()
							),
							Base64.decode(salt, Base64.DEFAULT),
							iter
						);

						return (KeyParameter) generator
							.generateDerivedMacParameters(
								cipherObj.getInt("ks")
							);
					}
				}
			);

			byte[] aesKey = keyParameter.getKey();
			Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
			SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey, "AES");

			aesCipher.init(
					Cipher.DECRYPT_MODE,
					aesKeySpec,
					new GCMParameterSpec(cipherObj.getInt("ts"), ivBytes)
			);

			msgObj.put(
					"content", new String(aesCipher.doFinal(ctBytes), "UTF-8")
			);

			resMessagesObjs.put(i, msgObj);
		}

		return new PluginResult(PluginResult.Status.OK, resMessagesObjs);
	}

}
