import java.security.MessageDigest;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.NaCl.Sodium;

import xdi2.core.syntax.CloudNumber;

public class CryptoCloudNumberFactory {

	public static void keys(byte[] pub, byte[] privpub) throws Exception {

		NaCl.init();
		Sodium sodium = NaCl.sodium();

		// create seed

		byte[] seed = new byte[256];

		sodium.randombytes(seed, 256);
		seed = sha256(seed);

		// create key pairs

		sodium.crypto_sign_ed25519_seed_keypair(pub, privpub, seed);
	}

	public static CloudNumber create(byte[] pub) throws Exception {

		String string = "=!:publickey-curve25519-base58-check:" + base58withappcodeandchecksum(pub);

		return CloudNumber.create(string);
	}

	static byte[] sha256(byte[] bytes) throws Exception {

		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(bytes);
		return digest.digest();
	}

	static String base58withappcodeandchecksum(byte[] key) throws Exception {

		byte[] bytes1 = new byte[33];
		bytes1[0] = 0x00;
		System.arraycopy(key, 0, bytes1, 1, 32);

		byte[] bytes2 = sha256(sha256(bytes1));

		byte[] bytes3 = new byte[37];
		System.arraycopy(bytes1, 0, bytes3, 0, 33);
		System.arraycopy(bytes2, 0, bytes3, 33, 4);

		return Base58.encode(bytes3);
	}
}
