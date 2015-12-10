package xdi2.example.ec25519.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;

import xdi2.client.impl.http.XDIHttpClient;
import xdi2.client.impl.websocket.XDIWebSocketClient;
import xdi2.client.impl.websocket.XDIWebSocketClient.Callback;
import xdi2.core.bootstrap.XDIBootstrap;
import xdi2.core.constants.XDIConstants;
import xdi2.core.features.linkcontracts.LinkContracts;
import xdi2.core.features.linkcontracts.instance.RootLinkContract;
import xdi2.core.security.ec25519.signature.create.EC25519StaticPrivateKeySignatureCreator;
import xdi2.core.security.ec25519.util.EC25519CloudNumberUtil;
import xdi2.core.security.ec25519.util.EC25519KeyPairGenerator;
import xdi2.core.syntax.CloudName;
import xdi2.core.syntax.CloudNumber;
import xdi2.core.syntax.XDIAddress;
import xdi2.core.syntax.XDIArc;
import xdi2.core.syntax.XDIStatement;
import xdi2.core.util.XDIAddressUtil;
import xdi2.messaging.Message;
import xdi2.messaging.MessageEnvelope;
import xdi2.messaging.operations.Operation;
import xdi2.messaging.response.MessagingResponse;
import xdi2.messaging.response.TransportMessagingResponse;


/**
 * 
 *  -------------------------
 * |                         |  
 * |  =bob's XDI ENDPOINT    |
 * |  =!:uuid:2222           |
 * |                         |
 *  -------------------------
 *    |                  |
 *    | WebSocket        | WebSocket
 *    |                  |
 *    |                  |
 *  AGENT 0            AGENT 1
 * 
 * 
 * both AGENT 0 and AGENT 1 have root link contracts with =bob
 * both AGENT 0 and AGENT 1 have cid-1 cryptographic XDI numbers
 * e.g. =!:cid-1:x3DSCpf5KBaFTt5h6tDyTkXa6WLZZcCyUdzDQ1PfVx2ivj8DGkZ
 * 
 * AGENT 1 has a $push link contract with =bob's endpoint
 * AGENT 0 will $set a new value for =bob's e-mail address
 * 
 */
public class WebSocketSendTest {

	static final CloudName BOB_CLOUDNAME = CloudName.create("=bob");
	static final CloudNumber BOB_CLOUDNUMBER = CloudNumber.create("=!:uuid:2222");
	static final URI BOB_URI_HTTP = URI.create("http://localhost:8080/graph2");
	static final URI BOB_URI_WEBSOCKET = URI.create("ws://localhost:8080/graph2");
	static final String BOB_SECRETTOKEN = "s3cr3t";

	static byte[][] AGENT_PUBLICKEY = new byte[2][32];
	static byte[][] AGENT_PRIVATEKEY = new byte[2][64];
	static CloudNumber[] AGENT_CLOUDNUMBER = new CloudNumber[2];
	static XDIAddress[] AGENT_LINKCONTRACT = new XDIAddress[2];
	static XDIWebSocketClient[] agentWebSocketClient = new XDIWebSocketClient[2]; 

	/*
	 * Here we set up a link contract that allows the agent to talk to the cloud.
	 * =bob (the cloud owner) creates these link contracts with his secret token.
	 */
	static void setupAgentLinkContract(int i) throws Exception {

		EC25519KeyPairGenerator.generateEC25519KeyPair(AGENT_PUBLICKEY[i], AGENT_PRIVATEKEY[i]);
		AGENT_CLOUDNUMBER[i] = EC25519CloudNumberUtil.createEC25519CloudNumber(XDIConstants.CS_AUTHORITY_PERSONAL, AGENT_PUBLICKEY[i]);

		MessageEnvelope connectME = new MessageEnvelope();
		Message connectM = connectME.createMessage(AGENT_CLOUDNUMBER[i].getXDIAddress());
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
		httpClient.close();

		AGENT_LINKCONTRACT[i] = LinkContracts.getAllLinkContracts(mr.getResultGraph()).next().getContextNode().getXDIAddress();
		System.out.println("SUCCESSFULLY SET UP LINK CONTRACT FOR AGENT " + i + ": " + AGENT_LINKCONTRACT[i]);
	}

	static void connectWebSocket(final int i) {

		agentWebSocketClient[i] = new XDIWebSocketClient(BOB_URI_WEBSOCKET);

		agentWebSocketClient[i].setCallback(new Callback() {

			@Override
			public void onMessageEnvelope(MessageEnvelope messageEnvelope) {

				System.out.println("WEBSOCKET " + i + " RECEIVED: ");
				System.out.println(messageEnvelope.getGraph().toString("XDI DISPLAY"));
			}

			@Override
			public void onMessagingResponse(TransportMessagingResponse messagingResponse) {

				System.out.println("WEBSOCKET " + i + " RECEIVED:");
				System.out.println(messagingResponse.getGraph().toString("XDI DISPLAY"));
			}
		});
	}

	static void setupAgentPushLinkContract(int i) throws Exception {

		MessageEnvelope connectME = new MessageEnvelope();
		Message connectM = connectME.createMessage(AGENT_CLOUDNUMBER[i].getXDIAddress());
		connectM.setToPeerRootXDIArc(BOB_CLOUDNUMBER.getPeerRootXDIArc());
		connectM.setLinkContractXDIAddress(AGENT_LINKCONTRACT[i]);
		Operation connectO = connectM.createConnectOperation(XDIBootstrap.PUSH_LINK_CONTRACT_TEMPLATE_ADDRESS);
		connectO.setVariableValue(XDIArc.create("{$push}"), BOB_CLOUDNUMBER.getXDIAddress());
		new EC25519StaticPrivateKeySignatureCreator(AGENT_PRIVATEKEY[i]).createSignature(connectM.getContextNode());

		agentWebSocketClient[i].send(connectME);
		System.out.println("SETTING UP PUSH CONTRACT FOR AGENT " + i);
		System.out.println(connectME.getGraph().toString("XDI DISPLAY"));
	}

	static void updateEmailAddress(int i, String newemail) throws Exception {

		MessageEnvelope setME = new MessageEnvelope();
		Message setM = setME.createMessage(AGENT_CLOUDNUMBER[i].getXDIAddress());
		setM.setToPeerRootXDIArc(BOB_CLOUDNUMBER.getPeerRootXDIArc());
		setM.setLinkContractXDIAddress(AGENT_LINKCONTRACT[i]);
		setM.createSetOperation(
				XDIStatement.fromLiteralComponents(
						XDIAddressUtil.concatXDIAddresses(BOB_CLOUDNUMBER.getXDIAddress(), XDIAddress.create("<#email>")), 
						newemail));
		new EC25519StaticPrivateKeySignatureCreator(AGENT_PRIVATEKEY[i]).createSignature(setM.getContextNode());

		System.out.println("AGENT " + i + " NOW UPDATES =bob's EMAIL ADDRESS...");
		agentWebSocketClient[i].send(setME);
		System.out.println(setME.getGraph().toString("XDI DISPLAY"));
	}

	public static void main(String[] args) throws Exception {

		// =bob adds two agent link contracts to his cloud
		setupAgentLinkContract(0);			// "connect to cloud"
		setupAgentLinkContract(1);

		// the two agents connect to =bob's cloud
		connectWebSocket(0);
		connectWebSocket(1);

		// agent 1 sets up push link contract for itself
		setupAgentPushLinkContract(1);

		// sleep a bit
		Thread.sleep(5000);

		// agent 0 changes something in the cloud
		updateEmailAddress(0, "bob@newemail.com");

		System.out.println("PRESS AND KEY TO EXIT...");
		new BufferedReader(new InputStreamReader(System.in)).readLine();
		System.out.println("EXITING...");
	}
}
