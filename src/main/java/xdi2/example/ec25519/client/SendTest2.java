package xdi2.example.ec25519.client;

import org.abstractj.kalium.encoders.Hex;

import xdi2.client.XDIClient;
import xdi2.client.impl.http.XDIHttpClient;
import xdi2.core.constants.XDIConstants;
import xdi2.core.features.linkcontracts.instance.GenericLinkContract;
import xdi2.core.security.ec25519.sign.EC25519StaticPrivateKeySignatureCreator;
import xdi2.core.security.ec25519.util.EC25519CloudNumberUtil;
import xdi2.core.security.ec25519.util.EC25519KeyPairGenerator;
import xdi2.core.syntax.CloudNumber;
import xdi2.core.syntax.XDIAddress;
import xdi2.messaging.Message;
import xdi2.messaging.MessageEnvelope;
import xdi2.messaging.response.MessagingResponse;

public class SendTest2 {

	public static void main(String[] args) throws Exception {

		byte[] publicKey = new byte[32], privateKey = new byte[64];

		EC25519KeyPairGenerator.generateEC25519KeyPair(publicKey, privateKey);
		System.out.println("ORIGINAL PUB: " + Hex.HEX.encode(publicKey));

		CloudNumber cloudNumber = EC25519CloudNumberUtil.createEC25519CloudNumber(XDIConstants.CS_AUTHORITY_PERSONAL, publicKey);
		System.out.println("ORIGINAL CN: " + cloudNumber);

		MessageEnvelope me = new MessageEnvelope();
		Message m = me.createMessage(cloudNumber.getXDIAddress());
		m.setToXDIAddress(XDIAddress.create("=!:uuid:2222"));
		m.setLinkContractXDIAddress(GenericLinkContract.createGenericLinkContractXDIAddress(XDIAddress.create("=!:uuid:2222"), XDIAddress.create("$test"), null));
		m.createGetOperation(XDIConstants.XDI_ADD_ROOT);

		EC25519StaticPrivateKeySignatureCreator sc = new EC25519StaticPrivateKeySignatureCreator(privateKey);
		sc.createSignature(m.getContextNode());

		System.out.println("MESSAGE ENVELOPE: ");
		System.out.println(me.getGraph().toString("XDI DISPLAY", null));

		XDIClient<?> client = new XDIHttpClient("http://localhost:9801/graph2");
		MessagingResponse mr = client.send(me);

		System.out.println("MESSAGE RESULT: ");
		System.out.println(mr.getResultGraph().toString("XDI DISPLAY", null));
	}
}
