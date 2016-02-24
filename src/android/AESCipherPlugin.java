package com.likemindnetworks.crypto;

import android.annotation.TargetApi;
import android.os.Build;

import com.google.common.io.ByteStreams;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCipherPlugin extends CordovaPlugin {

	private final static String CIPHER_MODE = "AES/CBC/PKCS5Padding";
	private final static int IV_BYTE_SIZE = 16;

	private final static SecureRandom secureRandom = new SecureRandom();

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
		if (action.equals("encryptFile") || action.equals("decryptFile")) {
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
		byte[] ivBytes = new byte[IV_BYTE_SIZE];
		secureRandom.nextBytes(ivBytes);

		Cipher aesCipher = Cipher.getInstance(CIPHER_MODE);
		aesCipher.init(
				Cipher.ENCRYPT_MODE,
				new SecretKeySpec(hexStringToByteArray(key), "AES"),
				new IvParameterSpec(ivBytes)
		);

		final InputStream fin = new FileInputStream(finPath);
		final OutputStream fout = new FileOutputStream(foutPath);

		try {
			// write out iv to output file first
			fout.write(ByteBuffer.allocate(4).putInt(IV_BYTE_SIZE).array());
			fout.write(ivBytes);

			ByteStreams.copy(fin, new CipherOutputStream(fout, aesCipher));
			fout.flush();
		} finally {
			fin.close();
			fout.close();
		}

		return new PluginResult(PluginResult.Status.OK);
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
			int ivSize;
			byte[] ivSizeBuffer = new byte[4];

			// parse iv size
			fin.read(ivSizeBuffer);
			ivSize = ByteBuffer.wrap(ivSizeBuffer).getInt();

			// read iv
			byte[] ivBytes = new byte[ivSize];
			fin.read(ivBytes);

			Cipher aesCipher = Cipher.getInstance(CIPHER_MODE);
			aesCipher.init(
					Cipher.DECRYPT_MODE,
					new SecretKeySpec(hexStringToByteArray(key), "AES"),
					new IvParameterSpec(ivBytes)
			);

			ByteStreams.copy(new CipherInputStream(fin, aesCipher), fout);
			fout.flush();
		} finally {
			fin.close();
			fout.close();
		}

		return new PluginResult(PluginResult.Status.OK);
	}

}
