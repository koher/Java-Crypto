package org.koherent.crypto;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hashes {
	private static final String ARGORITHM_NAME_MD5 = "MD5";
	private static final String ARGORITHM_NAME_SHA1 = "SHA-1";
	private static final String ARGORITHM_NAME_SHA256 = "SHA-256";

	private Hashes() {
	}

	private static String hash(InputStream in, String algorithmName)
			throws IOException {
		try {
			MessageDigest messageDigest = MessageDigest
					.getInstance(algorithmName);

			byte[] buffer = new byte[0x10000];
			int length;
			while ((length = in.read(buffer)) >= 0) {
				messageDigest.update(buffer, 0, length);
			}

			StringBuilder builder = new StringBuilder();

			for (byte b : messageDigest.digest()) {
				builder.append(String.format("%02x", b));
			}

			return builder.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new UnsupportedOperationException(e);
		}
	}

	private static String hash(byte[] bytes, String algorithmName) {
		try {
			return hash(new ByteArrayInputStream(bytes), algorithmName);
		} catch (IOException e) {
			throw new Error("Never happens.");
		}
	}

	private static String hash(String string, String algorithmName) {
		return hash(string.getBytes(), algorithmName);
	}

	private static String hash(File file, String algorithmName)
			throws FileNotFoundException, IOException {
		InputStream in = null;
		try {
			in = new BufferedInputStream(new FileInputStream(file));
			return hash(in, algorithmName);
		} finally {
			if (in != null) {
				in.close();
			}
		}
	}

	public static String md5(byte[] bytes) {
		return hash(bytes, ARGORITHM_NAME_MD5);
	}

	public static String md5(String string) {
		return hash(string, ARGORITHM_NAME_MD5);
	}

	public static String md5(File file) throws FileNotFoundException,
			IOException {
		return hash(file, ARGORITHM_NAME_MD5);
	}

	public static String sha1(byte[] bytes) {
		return hash(bytes, ARGORITHM_NAME_SHA1);
	}

	public static String sha1(String string) {
		return hash(string, ARGORITHM_NAME_SHA1);
	}

	public static String sha1(File file) throws FileNotFoundException,
			IOException {
		return hash(file, ARGORITHM_NAME_SHA1);
	}

	public static String sha256(byte[] bytes) {
		return hash(bytes, ARGORITHM_NAME_SHA256);
	}

	public static String sha256(String string) {
		return hash(string, ARGORITHM_NAME_SHA256);
	}

	public static String sha256(File file) throws FileNotFoundException,
			IOException {
		return hash(file, ARGORITHM_NAME_SHA256);
	}
}
