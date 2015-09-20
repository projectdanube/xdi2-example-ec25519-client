package xdi2.example.ec25519.client;
import java.security.PrivateKey;

import xdi2.client.XDIClient;
import xdi2.client.impl.http.XDIHttpClient;
import xdi2.client.util.XDIClientUtil;
import xdi2.core.constants.XDIConstants;
import xdi2.core.features.linkcontracts.instance.GenericLinkContract;
import xdi2.core.security.signature.create.RSAStaticPrivateKeySignatureCreator;
import xdi2.core.syntax.CloudNumber;
import xdi2.core.syntax.XDIAddress;
import xdi2.discovery.XDIDiscoveryClient;
import xdi2.discovery.XDIDiscoveryResult;
import xdi2.messaging.Message;
import xdi2.messaging.MessageEnvelope;
import xdi2.messaging.response.MessagingResponse;

public class SendTest1 {

	public static void main(String[] args) throws Exception {

		XDIDiscoveryResult r = XDIDiscoveryClient.DEFAULT_DISCOVERY_CLIENT.discover(XDIAddress.create("=markus"));
		PrivateKey priv = XDIClientUtil.retrieveSignaturePrivateKey(r.getCloudNumber(), r.getXdiEndpointUri(), "test11!!");

		CloudNumber cloudNumber = r.getCloudNumber();
		System.out.println("ORIGINAL CN: " + cloudNumber);

		MessageEnvelope me = new MessageEnvelope();
		Message m = me.createMessage(cloudNumber.getXDIAddress());
		m.setToXDIAddress(XDIAddress.create("=!:uuid:1111"));
		m.setLinkContractXDIAddress(GenericLinkContract.createGenericLinkContractXDIAddress(XDIAddress.create("=!:uuid:1111"), XDIAddress.create("$test"), null));
		m.createGetOperation(XDIConstants.XDI_ADD_ROOT);

		RSAStaticPrivateKeySignatureCreator sc = new RSAStaticPrivateKeySignatureCreator(priv);
		sc.createSignature(m.getContextNode());

		System.out.println("MESSAGE ENVELOPE: ");
		System.out.println(me.getGraph().toString("XDI DISPLAY", null));

		XDIClient<?> client = new XDIHttpClient("http://localhost:9801/graph1");
		MessagingResponse mr = client.send(me);

		System.out.println("MESSAGE RESULT: ");
		System.out.println(mr.getResultGraph().toString("XDI DISPLAY", null));
	}
}
