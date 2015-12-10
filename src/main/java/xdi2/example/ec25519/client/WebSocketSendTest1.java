package xdi2.example.ec25519.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;

import org.abstractj.kalium.encoders.Hex;

import xdi2.client.impl.http.XDIHttpClient;
import xdi2.client.impl.websocket.XDIWebSocketClient;
import xdi2.client.impl.websocket.XDIWebSocketClient.Callback;
import xdi2.core.bootstrap.XDIBootstrap;
import xdi2.core.constants.XDIConstants;
import xdi2.core.features.linkcontracts.LinkContracts;
import xdi2.core.features.linkcontracts.instance.RootLinkContract;
import xdi2.core.security.ec25519.crypto.EC25519Provider;
import xdi2.core.security.ec25519.crypto.RandomProvider;
import xdi2.core.security.ec25519.crypto.SHA256Provider;
import xdi2.core.security.ec25519.signature.create.EC25519StaticPrivateKeySignatureCreator;
import xdi2.core.security.ec25519.util.EC25519CloudNumberUtil;
import xdi2.core.security.ec25519.util.EC25519KeyPairGenerator;
import xdi2.core.syntax.CloudName;
import xdi2.core.syntax.CloudNumber;
import xdi2.core.syntax.XDIAddress;
import xdi2.core.syntax.XDIArc;
import xdi2.messaging.Message;
import xdi2.messaging.MessageEnvelope;
import xdi2.messaging.operations.Operation;
import xdi2.messaging.response.MessagingResponse;
import xdi2.messaging.response.TransportMessagingResponse;


/**
 */
public class WebSocketSendTest1 {

	static final CloudName BOB_CLOUDNAME = CloudName.create("=bob");
	static final CloudNumber BOB_CLOUDNUMBER = CloudNumber.create("=!:uuid:2222");
	static final URI BOB_URI_HTTP = URI.create("http://localhost:9801/graph2");
	static final URI BOB_URI_WEBSOCKET = URI.create("ws://localhost:9801/graph2");
	static final String BOB_SECRETTOKEN = "s3cr3t";

	static byte[] AGENT_PUBLICKEY = new byte[32];
	static byte[] AGENT_PRIVATEKEY = new byte[64];
	static CloudNumber AGENT_CLOUDNUMBER;
	static XDIAddress AGENT_LINKCONTRACT;

	static XDIWebSocketClient webSocketClient; 

	static void setupAgentLinkContract() throws Exception {

		EC25519KeyPairGenerator.generateEC25519KeyPair(AGENT_PUBLICKEY, AGENT_PRIVATEKEY);
		System.out.println("ORIGINAL PUB: " + Hex.HEX.encode(AGENT_PUBLICKEY));

		AGENT_CLOUDNUMBER = EC25519CloudNumberUtil.createEC25519CloudNumber(XDIConstants.CS_AUTHORITY_PERSONAL, AGENT_PUBLICKEY);
		System.out.println("ORIGINAL CN: " + AGENT_CLOUDNUMBER);

		MessageEnvelope connectME = new MessageEnvelope();
		Message connectM = connectME.createMessage(AGENT_CLOUDNUMBER.getXDIAddress());
		connectM.setToPeerRootXDIArc(BOB_CLOUDNUMBER.getPeerRootXDIArc());
		connectM.createConnectOperation(XDIBootstrap.ALL_LINK_CONTRACT_TEMPLATE_ADDRESS);

		MessageEnvelope sendME = new MessageEnvelope();
		Message sendM = sendME.createMessage(BOB_CLOUDNUMBER.getXDIAddress());
		sendM.setToPeerRootXDIArc(BOB_CLOUDNUMBER.getPeerRootXDIArc());
		sendM.setSecretToken(BOB_SECRETTOKEN);
		sendM.setLinkContractClass(RootLinkContract.class);
		sendM.createSendOperation(connectM);

		XDIHttpClient httpClient = new XDIHttpClient(BOB_URI_HTTP);
		MessagingResponse mr = httpClient.send(sendME);
		System.out.println("HTTP MESSAGING RESPONSE:");
		System.out.println(mr.getGraph().toString("XDI DISPLAY"));
		httpClient.close();

		AGENT_LINKCONTRACT = LinkContracts.getAllLinkContracts(mr.getResultGraph()).next().getContextNode().getXDIAddress();
		System.out.println("Found agent link contract: " + AGENT_LINKCONTRACT);
	}

	static void connectWebSocket() {

		webSocketClient = new XDIWebSocketClient(BOB_URI_WEBSOCKET);

		webSocketClient.setCallback(new Callback() {

			@Override
			public void onMessageEnvelope(MessageEnvelope messageEnvelope) {

				System.out.println("WEBSOCKET MESSAGE ENVELOPE:");
				System.out.println(messageEnvelope.getGraph().toString("XDI DISPLAY"));
			}

			@Override
			public void onMessagingResponse(TransportMessagingResponse messagingResponse) {

				System.out.println("WEBSOCKET MESSAGING RESPONSE:");
				System.out.println(messagingResponse.getGraph().toString("XDI DISPLAY"));
			}
		});
	}

	static void setupAgentPushLinkContract() throws Exception {

		MessageEnvelope connectME = new MessageEnvelope();
		Message connectM = connectME.createMessage(AGENT_CLOUDNUMBER.getXDIAddress());
		connectM.setToPeerRootXDIArc(BOB_CLOUDNUMBER.getPeerRootXDIArc());
		connectM.setLinkContractXDIAddress(AGENT_LINKCONTRACT);
		Operation connectO = connectM.createConnectOperation(XDIBootstrap.PUSH_LINK_CONTRACT_TEMPLATE_ADDRESS);
		connectO.setVariableValue(XDIArc.create("{$push}"), XDIConstants.XDI_ADD_ROOT);
		new EC25519StaticPrivateKeySignatureCreator(AGENT_PRIVATEKEY).createSignature(connectM.getContextNode());

		webSocketClient.send(connectME);
	}

	public static void main(String[] args) throws Exception {

		setupAgentLinkContract();
		connectWebSocket();
		setupAgentPushLinkContract();

		System.out.println("Press any key to exit...");
		new BufferedReader(new InputStreamReader(System.in)).readLine();
		System.out.println("Exiting...");
	}
}
