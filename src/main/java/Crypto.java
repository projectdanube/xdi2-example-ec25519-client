import java.nio.charset.Charset;
import java.util.Arrays;

import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.NaCl.Sodium;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jnr.ffi.byref.LongLongByReference;
import xdi2.core.features.signatures.Signature;
import xdi2.core.features.signatures.Signatures.NoSignaturesCopyStrategy;
import xdi2.core.io.Normalization;

public class Crypto {

	private static final Logger log = LoggerFactory.getLogger(Crypto.class);

	public static void sign(Signature<?, ?> s, byte[] privpub) throws Exception {

		byte[] input = Normalization.serialize(s.getBaseContextNode(), new NoSignaturesCopyStrategy()).getBytes(Charset.forName("UTF-8"));

		log.info("normalized msg: " + new String(Hex.encodeHex(input)));
		log.info("privpub: " + new String(Hex.encodeHex(privpub)));

		byte[] buffer = new byte[Sodium.SIGNATURE_BYTES + input.length];
		Arrays.fill(buffer, 0, Sodium.SIGNATURE_BYTES, (byte) 0);
		System.arraycopy(input, 0, buffer, Sodium.SIGNATURE_BYTES, input.length);
		LongLongByReference bufferLen = new LongLongByReference();

		int ret = NaCl.sodium().crypto_sign_ed25519(buffer, bufferLen, input, input.length, privpub);
		if (ret != 0) throw new RuntimeException("Crypto error.");

		buffer = Arrays.copyOfRange(buffer, 0, Sodium.SIGNATURE_BYTES);

		log.info("sig: " + new String(Hex.encodeHex(buffer)));

		s.setValue(new String(Base64.encodeBase64(buffer), "UTF-8"));
	}

	public static void validate(Signature<?, ?> s, byte[] pub) throws Exception {

		byte[] msg = Normalization.serialize(s.getBaseContextNode(), new NoSignaturesCopyStrategy()).getBytes(Charset.forName("UTF-8"));

		log.info("normalized msg: " + new String(Hex.encodeHex(msg)));
		log.info("pub: " + new String(Hex.encodeHex(pub)));

		byte[] sig = Base64.decodeBase64(s.getValue().getBytes("UTF-8"));

		log.info("sig: " + new String(Hex.encodeHex(sig)));

		byte[] sigAndMsg = new byte[sig.length + msg.length];
		System.arraycopy(sig, 0, sigAndMsg, 0, sig.length);
		System.arraycopy(msg, 0, sigAndMsg, sig.length, msg.length);

		byte[] buffer = new byte[sigAndMsg.length];
		LongLongByReference bufferLen = new LongLongByReference();

		int ret = NaCl.sodium().crypto_sign_ed25519_open(buffer, bufferLen, sigAndMsg, sigAndMsg.length, pub);
		if (ret != 0) throw new RuntimeException("Crypto error.");

		buffer = Arrays.copyOf(buffer, buffer.length - Sodium.SIGNATURE_BYTES);
		if (! Arrays.equals(msg, buffer)) throw new RuntimeException("Crypto error.");
	}
}
