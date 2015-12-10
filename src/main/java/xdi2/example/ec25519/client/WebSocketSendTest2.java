package xdi2.example.ec25519.client;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;

import xdi2.client.constants.XDIClientConstants;
import xdi2.client.impl.websocket.XDIWebSocketClient;
import xdi2.client.impl.websocket.XDIWebSocketClient.Callback;
import xdi2.core.constants.XDIConstants;
import xdi2.core.features.linkcontracts.instance.RootLinkContract;
import xdi2.core.syntax.XDIAddress;
import xdi2.discovery.XDIDiscoveryClient;
import xdi2.discovery.XDIDiscoveryResult;
import xdi2.messaging.Message;
import xdi2.messaging.MessageEnvelope;
import xdi2.messaging.response.FutureMessagingResponse;
import xdi2.messaging.response.TransportMessagingResponse;


/**
 * This shows how a cloud name can be "remembered" as part of a relationship
 * between two XDI authorities. This should not replace the need to properly
 * discover cloud names from cloud numbers, but can be used a supplementary tool.
 * 
 * This simple exampe assumes that there is only one cloud name per cloud number,
 * and that there is notion of "preferred" cloud names.
 */
public class WebSocketSendTest2 {

	public static void main(String[] args) throws Exception {

		XDIDiscoveryResult r = XDIDiscoveryClient.DEFAULT_DISCOVERY_CLIENT.discover(XDIAddress.create("=alice"), XDIClientConstants.WEBSOCKET_ENDPOINT_URI_TYPE);
		URI uri = r.getXdiWebSocketEndpointUri();

		System.out.println("Discovered WebSocket endpoint URI: " + uri);

		MessageEnvelope me = new MessageEnvelope();
		Message m = me.createMessage(r.getCloudNumber().getXDIAddress());
		m.setToPeerRootXDIArc(r.getCloudNumber().getPeerRootXDIArc());
		m.setSecretToken("alice");
		m.setLinkContractClass(RootLinkContract.class);
		m.createGetOperation(XDIConstants.XDI_ADD_ROOT);

		XDIWebSocketClient w = new XDIWebSocketClient(uri);
		FutureMessagingResponse f = w.send(me);

		w.setCallback(new Callback() {

			@Override
			public void onMessageEnvelope(MessageEnvelope messageEnvelope) {

				System.out.println("MESSAGE ENVELOPE:");
				System.out.println(messageEnvelope.getGraph().toString("XDI DISPLAY"));
			}

			@Override
			public void onMessagingResponse(TransportMessagingResponse messagingResponse) {

				System.out.println("MESSAGING RESPONSE:");
				System.out.println(messagingResponse.getGraph().toString("XDI DISPLAY"));
			}
		});

		System.out.println("Press any key to exit...");
		new BufferedReader(new InputStreamReader(System.in)).readLine();
		w.close();
		System.out.println("Exiting...");
	}
}
