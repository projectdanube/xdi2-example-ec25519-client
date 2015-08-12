
import org.abstractj.kalium.encoders.Hex;

import xdi2.client.XDIClient;
import xdi2.client.impl.http.XDIHttpClient;
import xdi2.core.constants.XDIConstants;
import xdi2.core.features.linkcontracts.instance.GenericLinkContract;
import xdi2.core.features.signatures.Signature;
import xdi2.core.syntax.CloudNumber;
import xdi2.core.syntax.XDIAddress;
import xdi2.messaging.Message;
import xdi2.messaging.MessageEnvelope;
import xdi2.messaging.response.MessagingResponse;

public class SendTest2 {

	public static void main(String[] args) throws Exception {

		byte[] pub = new byte[32], privpub = new byte[64];

		CryptoCloudNumberFactory.keys(pub, privpub);
		System.out.println("ORIGINAL PUB: " + Hex.HEX.encode(pub));

		CloudNumber cloudNumber = CryptoCloudNumberFactory.create(pub);
		System.out.println("ORIGINAL CN: " + cloudNumber);

		MessageEnvelope me = new MessageEnvelope();
		Message m = me.createMessage(cloudNumber.getXDIAddress());
		m.setToXDIAddress(XDIAddress.create("=!:uuid:2222"));
		m.setLinkContractXDIAddress(GenericLinkContract.createGenericLinkContractXDIAddress(XDIAddress.create("=!:uuid:2222"), XDIAddress.create("$test"), null));
		m.createGetOperation(XDIConstants.XDI_ADD_ROOT);

		Signature<?, ?> s = m.createSignature(null, null, null, null, true);
		Crypto.sign(s, privpub);

		System.out.println("MESSAGE ENVELOPE: ");
		System.out.println(me.getGraph().toString("XDI DISPLAY", null));

		XDIClient client = new XDIHttpClient("http://localhost:9801/graph2");
		MessagingResponse mr = client.send(me);

		System.out.println("MESSAGE RESULT: ");
		System.out.println(mr.getResultGraph().toString("XDI DISPLAY", null));
	}
}
