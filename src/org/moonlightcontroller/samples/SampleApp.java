package org.moonlightcontroller.samples;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import org.moonlightcontroller.bal.BoxApplication;
import org.moonlightcontroller.blocks.Discard;
import org.moonlightcontroller.blocks.FromDevice;
import org.moonlightcontroller.blocks.FromDump;
import org.moonlightcontroller.blocks.HeaderClassifier;
import org.moonlightcontroller.blocks.HeaderClassifier.HeaderClassifierRule;
import org.moonlightcontroller.blocks.ToDevice;
import org.moonlightcontroller.blocks.ToDump;
import org.moonlightcontroller.events.IAlertListener;
// import org.moonlightcontroller.blocks.ToDevice;
import org.moonlightcontroller.events.IHandleClient;
import org.moonlightcontroller.events.IInstanceUpListener;
import org.moonlightcontroller.events.InstanceAlertArgs;
import org.moonlightcontroller.events.InstanceUpArgs;
import org.moonlightcontroller.managers.models.IRequestSender;
import org.moonlightcontroller.managers.models.messages.Alert;
import org.moonlightcontroller.managers.models.messages.AlertMessage;
import org.moonlightcontroller.managers.models.messages.Error;
import org.moonlightcontroller.managers.models.messages.IMessage;
import org.moonlightcontroller.managers.models.messages.ReadResponse;
import org.moonlightcontroller.processing.Connector;
import org.moonlightcontroller.processing.IConnector;
import org.moonlightcontroller.processing.IProcessingBlock;
import org.moonlightcontroller.processing.ProcessingGraph;
import org.openboxprotocol.exceptions.InstanceNotAvailableException;
import org.openboxprotocol.protocol.HeaderField;
import org.openboxprotocol.protocol.HeaderMatch;
import org.openboxprotocol.protocol.IStatement;
import org.openboxprotocol.protocol.OpenBoxHeaderMatch;
import org.openboxprotocol.protocol.Priority;
import org.openboxprotocol.protocol.Statement;
import org.openboxprotocol.protocol.topology.IApplicationTopology;
import org.openboxprotocol.protocol.topology.InstanceLocationSpecifier;
import org.openboxprotocol.protocol.topology.TopologyManager;
import org.openboxprotocol.types.TransportPort;

import com.google.common.collect.ImmutableList;

public class SampleApp extends BoxApplication{

	private final static Logger LOG = Logger.getLogger(SampleApp.class.getName());
	
	public static final String PROPERTIES_PATH = "SampleApp.properties";

	public static final String PROP_SEGMENT = "segment";
	public static final String PROP_IN_IFC = "in_ifc";
	public static final String PROP_OUT_IFC = "out_ifc";
	public static final String PROP_IN_DUMP = "in_dump";
	public static final String PROP_OUT_DUMP = "out_dump";
	public static final String PROP_IN_USE_IFC = "in_use_ifc";
	public static final String PROP_OUT_USE_IFC = "out_use_ifc";
	public static final String PROP_ALERT = "alert";
	public static final String PROP_PORT_BLOCK = "port_block";
	
	public static final String DEFAULT_SEGMENT = "220";
	public static final String DEFAULT_IN_IFC = "eth0";
	public static final String DEFAULT_OUT_IFC = "eth0";
	public static final String DEFAULT_IN_DUMP = "in_dump.pcap";
	public static final String DEFAULT_OUT_DUMP = "out_dump.pcap";
	public static final String DEFAULT_IN_USE_IFC = "true";
	public static final String DEFAULT_OUT_USE_IFC = "true";
	public static final String DEFAULT_ALERT = "true";
	public static final String DEFAULT_PORT_BLOCK = "80";
	
	private static final Properties DEFAULT_PROPS = new Properties();
	
	static {
		DEFAULT_PROPS.setProperty(PROP_SEGMENT, DEFAULT_SEGMENT);
		DEFAULT_PROPS.setProperty(PROP_IN_IFC, DEFAULT_IN_IFC);
		DEFAULT_PROPS.setProperty(PROP_OUT_IFC, DEFAULT_OUT_IFC);
		DEFAULT_PROPS.setProperty(PROP_IN_DUMP, DEFAULT_IN_DUMP);
		DEFAULT_PROPS.setProperty(PROP_OUT_DUMP, DEFAULT_OUT_DUMP);
		DEFAULT_PROPS.setProperty(PROP_IN_USE_IFC, DEFAULT_IN_USE_IFC);
		DEFAULT_PROPS.setProperty(PROP_OUT_USE_IFC, DEFAULT_OUT_USE_IFC);
		DEFAULT_PROPS.setProperty(PROP_ALERT, DEFAULT_ALERT);
		DEFAULT_PROPS.setProperty(PROP_PORT_BLOCK, DEFAULT_PORT_BLOCK);
	}
	
	private Properties props;
	
	public SampleApp() {
		super("SampleApp");
		
		props = new Properties(DEFAULT_PROPS);
		File f = new File(PROPERTIES_PATH);
		try {
			props.load(new FileReader(f));
		} catch (IOException e) {
			LOG.severe("Cannot load properties file from path: " + f.getAbsolutePath());
			LOG.severe("Using default properties.");
		}
		LOG.info(String.format("SampleApp is running on Segment %s", props.getProperty(PROP_SEGMENT)));
		LOG.info(String.format("[->] Input: %s", (Boolean.parseBoolean(props.getProperty(PROP_IN_USE_IFC)) ? props.getProperty(PROP_IN_IFC) : props.getProperty(PROP_IN_DUMP))));
		LOG.info(String.format("[<-] Output: %s", (Boolean.parseBoolean(props.getProperty(PROP_OUT_USE_IFC)) ? props.getProperty(PROP_OUT_IFC) : props.getProperty(PROP_OUT_DUMP))));
		LOG.info(String.format("[!!] Alert is %s", (Boolean.parseBoolean(props.getProperty(PROP_ALERT)) ? "on" : "off")));
		LOG.info(String.format("[>|] Dropping packets with TCP_DST port %s", props.getProperty(PROP_PORT_BLOCK)));
		
		this.setStatements(createStatements());
		this.setInstanceUpListener(new InstanceUpHandler());
		this.setAlertListener(new FirewallAlertListener());
	}
	
	@Override
	public void handleAppStart(IApplicationTopology top, IHandleClient handles) {
		LOG.info("Got App Start Event");
		new Thread(()-> {
			for (int i = 0 ; i < 10; i++){
				try {
					handles.readHandle(
							new InstanceLocationSpecifier(22), 
							"monkey",
							"buisness", new FirewallRequestSender());
				} catch (InstanceNotAvailableException e1) {
					LOG.warning("Unable to reach OBI");
				}
				try {
					Thread.sleep(10000);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}).start();
	}
	
	private class FirewallAlertListener implements IAlertListener {
		
		@Override
		public void Handle(InstanceAlertArgs args) {
			Alert alert = args.getAlert();
			for (AlertMessage msg : alert.getMessages()) {
				LOG.info("got an alert from block:" + args.getBlock().getId() + "::" + msg.getMessage());
				LOG.info("Packet data: " + msg.getPacket());
			}
			
		}
	}
	
	private class FirewallRequestSender implements IRequestSender {

		@Override
		public void onSuccess(IMessage message) {
			if (message instanceof ReadResponse){
				ReadResponse rr = (ReadResponse)message;
				LOG.info("got a read response:" + rr.getBlockId() + "::" + rr.getReadHandle() + "::" + rr.getResult());
			}			
		}

		@Override
		public void onFailure(Error err) {
			LOG.info("got an error:" + err.getError_type() + "::" + err.getMessage());
		}
	}

	private List<IStatement> createStatements() {

		int portBlock;
		try {
			portBlock = Integer.parseInt(props.getProperty(PROP_PORT_BLOCK));
		} catch (NumberFormatException e) {
			portBlock = Integer.parseInt(DEFAULT_PORT_BLOCK);
			LOG.info("Error parsing port_block property. Blocking default port: " + portBlock);
		}
		
		HeaderMatch h1 = new OpenBoxHeaderMatch.Builder().setExact(HeaderField.TCP_DST, new TransportPort(portBlock)).build();
		HeaderMatch h2 = new OpenBoxHeaderMatch.Builder().build();
		
		ArrayList<HeaderClassifierRule> rules = new ArrayList<HeaderClassifierRule>(Arrays.asList(
				new HeaderClassifierRule.Builder().setHeaderMatch(h1).setPriority(Priority.HIGH).setOrder(0).build(),
				new HeaderClassifierRule.Builder().setHeaderMatch(h2).setPriority(Priority.MEDIUM).setOrder(1).build()));

		FromDevice fromDevice = new FromDevice("FromDevice_SampleApp", props.getProperty(PROP_IN_IFC), true, true);
		ToDevice toDevice = new ToDevice("ToDevice_SampleApp", props.getProperty(PROP_OUT_IFC));
		FromDump fromDump = new FromDump("FromDump_SampleApp", props.getProperty(PROP_IN_DUMP), false, true);
		ToDump toDump = new ToDump("ToDump_SampleApp", props.getProperty(PROP_OUT_DUMP));
		HeaderClassifier classify = new HeaderClassifier("HeaderClassifier_SampleApp", rules, Priority.HIGH);
		org.moonlightcontroller.blocks.Alert alert = 
				new org.moonlightcontroller.blocks.Alert("Alert_SampleApp", "Alert from SampleApp", 1, true, 1000);
		Discard discard = new Discard("Discard_SampleApp");

		IProcessingBlock from = (Boolean.parseBoolean(props.getProperty(PROP_IN_USE_IFC))) ?
				fromDevice : fromDump;
		
		IProcessingBlock to = (Boolean.parseBoolean(props.getProperty(PROP_OUT_USE_IFC))) ?
				toDevice : toDump;
		
		List<IConnector> connectors = new ArrayList<>();
		List<IProcessingBlock> blocks = new ArrayList<>();
		
		blocks.addAll(ImmutableList.of(from, to, classify, discard));
		connectors.addAll(ImmutableList.of(
			new Connector.Builder().setSourceBlock(from).setSourceOutputPort(0).setDestBlock(classify).build(),
			new Connector.Builder().setSourceBlock(classify).setSourceOutputPort(1).setDestBlock(to).build()
		));
		
		if (Boolean.parseBoolean(props.getProperty(PROP_ALERT))) {
			blocks.add(alert);
			connectors.add(new Connector.Builder().setSourceBlock(classify).setSourceOutputPort(0).setDestBlock(alert).build());
			connectors.add(new Connector.Builder().setSourceBlock(alert).setSourceOutputPort(0).setDestBlock(discard).build());
	 	} else {
			connectors.add(new Connector.Builder().setSourceBlock(classify).setSourceOutputPort(0).setDestBlock(discard).build());
	 	}
		
		int segment;
		try {
			segment = Integer.parseInt(props.getProperty(PROP_SEGMENT));
		} catch (NumberFormatException e) {
			segment = Integer.parseInt(DEFAULT_SEGMENT);
			LOG.info("Error parsing segment property. Using default segment: " + segment);
		}
		
		IStatement st = new Statement.Builder()
			.setLocation(TopologyManager.getInstance().resolve(segment))
			.setProcessingGraph(new ProcessingGraph.Builder().setBlocks(blocks).setConnectors(connectors).setRoot(from).build())
			.build();
		
		return Collections.singletonList(st);
	}
	
	private class InstanceUpHandler implements IInstanceUpListener {

		@Override
		public void Handle(InstanceUpArgs args) {
			LOG.info("Instance up for firewall: " + args.getInstance().toString());	
		}
	}

}