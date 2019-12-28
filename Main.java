package com.company;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.protocol.Protocol;
import sun.misc.Unsafe;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import java.io.*;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.lang.reflect.Method;
import java.net.URL;
import java.rmi.server.*;
import java.util.*;
import java.util.logging.*;

class RawFrame {
    public long id;
    public Buffer data;
    RawFrame(long _id, Buffer _data) {
        id = _id;
        data = _data;
    }
}
class RawMessage {
    public long id;
    public long ack;
    public long seq;
    public List<RawFrame> data;
    RawMessage(long _id, long _ack, long _seq, List<RawFrame> _data) {
        id = _id;
        ack = _ack;
        seq = _seq;
        data = _data;
    }
}

class RawStream {
    public List<RawMessage> queue;
    RawStream() {
        queue = new ArrayList<RawMessage>();
    }
    int addMsg(RawMessage msg) {
        int id = queue.size();
        queue.add(msg);
        return id;
    }
}

class RMIHandler implements PacketHandler {
    private HashSet<Integer> ports;
    public HashMap<Long, HashMap<Integer, RawStream>> streams;
    RMIParser parser;
    private long current_id;

    RMIHandler(RMIParser _parser, HashSet<Integer> _ports) {
        ports = _ports;
        streams = new HashMap<Long, HashMap<Integer, RawStream>>();
        parser = _parser;
        current_id = 0;
    }
    private int searchAck(RawStream stream, long value) {
        if (stream == null)
            return -1;
        for (int i = 0; i < stream.queue.size(); ++i) {
            if (stream.queue.get(i).ack == value)
                return i;
        }
        return -1;
    }
    private long genCommunicationHash(TCPPacket pkt) {
        int src = pkt.getParentPacket().getSourceIP().hashCode();
        int dst = pkt.getParentPacket().getDestinationIP().hashCode();
        if (dst > src) {
            return (((dst & 0xffffffff) << 32) | (src & 0xffffffff));
        } else {
            return (((src & 0xffffffff) << 32) | (dst & 0xffffffff));
        }
    }
    @Override
    public boolean nextPacket(final Packet packet) throws IOException {
        ++current_id;
        if (packet.hasProtocol(Protocol.TCP)) {
            TCPPacket pkt = (TCPPacket)packet.getPacket(Protocol.TCP);
            long com_hash = genCommunicationHash(pkt);
            RawFrame payload = new RawFrame(current_id, pkt.getPayload());
            if (payload.data == null)
                return true;
            Integer port = -1;
            if (ports.contains(pkt.getSourcePort()))
                port = pkt.getSourcePort();
            if (ports.contains(pkt.getDestinationPort()))
                port = pkt.getDestinationPort();
            if (port > 0) {
                //Instant time = Instant.ofEpochMilli(packet.getArrivalTime() / 1000);
                if (!streams.containsKey(com_hash))
                    streams.put(com_hash, new HashMap<Integer, RawStream>());
                RawStream stream = streams.get(com_hash).getOrDefault(port, new RawStream());
                int queueID = searchAck(stream, pkt.getAcknowledgementNumber());
                if (queueID == -1) {
                    queueID = searchAck(stream, pkt.getSequenceNumber());
                    if (queueID >= 0) {
                        parser.decode(stream.queue.get(queueID));
                        ports.addAll(parser.new_ports);
                        // HACK: for case when client send enpointinfo during ProtocolSYN
                        // tried to catch ProtocolAck
                        if (stream.queue.get(queueID).data.get(0).data.getArray()[0] == 0x4e)
                            return true;
                    }
                    RawMessage msg = new RawMessage(
                            current_id, pkt.getAcknowledgementNumber(),
                            pkt.getSequenceNumber(), new ArrayList<RawFrame>()
                    );
                    msg.data.add(payload);
                    stream.addMsg(msg);
                    streams.get(com_hash).put(port, stream);
                } else {
                    stream.queue.get(queueID).data.add(payload);
                }

            }
        }
        return true;
    }
}
class PatchedReferenceQueue<T> extends ReferenceQueue<T> {
    @Override
    public Reference<? extends T> remove(long timeout) throws IllegalArgumentException, InterruptedException {
        super.remove(timeout);
        return null;
    }
}
class PatchedHashMap<K,V> extends HashMap<K, V> {
    public Boolean patched;
    public Class target;
    @Override
    public V get(Object key) {
        if (patched) {
            Main.logger.fine(String.format("Called PatchedHashMap.get with %s", key));
            return null;
        } else {
            return super.get(key);
        }
    }

    @Override
    public V put(K key, V value) {
        if (patched) {
            Main.logger.fine(String.format("Called PatchedHashMap.put with %s", value));
            try {
                Field field = value.getClass().getDeclaredField("dgc");
                field.setAccessible(true);
                field.set(value, null);

                Field field2 = value.getClass().getDeclaredField("refQueue");
                field2.setAccessible(true);
                field2.set(value, new PatchedReferenceQueue<LiveRef>());

            } catch (Exception err) {
                Main.logger.severe(String.format("Error in nulling dgc field: %s", err));
            }
            return super.put(key, value);
        } else {
            return super.put(key, value);
        }
    }
    PatchedHashMap(int initialCapacity, Class _target) {
        super(initialCapacity);
        target = _target;
        patched = false;
    }
    void patch() {
        patched = true;
    }
}
class HackDGC {
    private PatchedHashMap<Object, Object> pathced_table;
    private Field dgc_endpointentry_table;
    private HashMap<Object, Object> old_table;
    HackDGC() {
        pathced_table = null;
        dgc_endpointentry_table = null;
        old_table = null;
        try {
            Class dgc = Class.forName("sun.rmi.transport.DGCClient");
            Class dgc_endpointentry = dgc.getDeclaredClasses()[0];
            dgc_endpointentry_table = dgc_endpointentry.getDeclaredFields()[14];
            dgc_endpointentry_table.setAccessible(true);
            pathced_table = new PatchedHashMap<Object, Object>(5, dgc_endpointentry);
            old_table = (HashMap<Object, Object>) dgc_endpointentry_table.get(null);
            pathced_table.putAll(old_table);
            dgc_endpointentry_table.set(null, pathced_table);
            pathced_table.patched = true;
        } catch (Exception err) {
            Main.logger.severe(String.format("Error in creating HackDGC: %s", err));
        }
    }
    public void close() throws Exception {
        if (pathced_table == null || dgc_endpointentry_table == null || old_table == null) {
            ;
        } else {
            pathced_table.patched = false;
            dgc_endpointentry_table.set(null, old_table);
            dgc_endpointentry_table.setAccessible(false);
        }
    }
}
class RMIParser {
    private Map<ObjID, AbstractMap.SimpleEntry<String, Map<Long, Method>>> remote_interface_map_ext;
    public HashSet<Integer> new_ports;
    private Map<Long, Method> unanswered_calls;
    public RMIParser(Map<ObjID, AbstractMap.SimpleEntry<String, Map<Long, Method>>> _remote_interface_map_ext) {
        remote_interface_map_ext = _remote_interface_map_ext;
        new_ports = new HashSet<Integer>();
        unanswered_calls = new HashMap<Long, Method>();
    }
    private byte [] join_substream(ListIterator<RawFrame> it) {
        ByteArrayOutputStream result = new ByteArrayOutputStream( );
        try {
            while (it.hasNext()) {
                result.write(it.next().data.getArray());
            }
        } catch (IOException err) {
            Main.logger.severe(String.format("Error in stream joining: %s", err));
        }
        return result.toByteArray( );
    }
    public void decode(RawMessage msg) {
        ListIterator<RawFrame> it = msg.data.listIterator();
        while (it.hasNext()) {
            RawFrame frame = it.next();
            byte[] data = frame.data.getArray();
            int opcode = data[0];
            switch (opcode) {
                case 0x4a:
                    byte[] magic = {0x52, 0x4d, 0x49};
                    if (Arrays.equals(Arrays.copyOfRange(data, 1, 4), magic)) {
                        Main.logger.fine("Protocol SYN");
                    }
                    break;
                case 0x4e:
                    Main.logger.fine("Protocol ACK");
                    break;
                case 0x50:
                    Main.logger.fine("Call");
                    data = join_substream(msg.data.listIterator(it.nextIndex() - 1));
                    data = Arrays.copyOfRange(data, 1, data.length);
                    if (!parseCall(msg.ack, data)) {
                        Main.logger.severe(String.format("last frame id: %d", msg.data.get(msg.data.size() - 1).id));
                    }
                    return;
                case 0x51:
                    Main.logger.fine("Return data");
                    data = join_substream(msg.data.listIterator(it.nextIndex() - 1));
                    data = Arrays.copyOfRange(data, 1, data.length);
                    if (!parseReturn(msg.seq, data)) {
                        Main.logger.severe(String.format("last frame id: %d", msg.data.get(msg.data.size() - 1).id));
                    }
                    return;
                case 0x52:
                    Main.logger.fine("Ping");
                    break;
                case 0x53:
                    Main.logger.fine("Pong");
                    break;
                case 0x54:
                    Main.logger.fine("DgcAck");
                    break;
                default:
                    System.out.println("Unknown message\n");
            }
        }
    }
    private Object parseType(Class remtype, ObjectInputStream ois) throws Exception {
        if (remtype.getName().equals("long")) {
            return ois.readLong();
        }
        if (remtype.getName().equals("int")) {
            return ois.readInt();
        }
        if (remtype.getName().equals("short")) {
            return ois.readShort();
        }
        if (remtype.getName().equals("byte")) {
            return ois.readByte();
        }
        if (remtype.getName().equals("float")) {
            return ois.readFloat();
        }
        if (remtype.getName().equals("double")) {
            return ois.readDouble();
        }
        if (remtype.getName().equals("boolean")) {
            return ois.readBoolean();
        }
        if (remtype.getName().equals("void")) {
            return null;
        }
        HackDGC hacked = new HackDGC();
        Object result = ois.readObject();
        hacked.close();
        return result;
    }
    private List<Object> parseCallArguments(long ack, Method method, ObjectInputStream ois) {
        List<Object> args = new ArrayList();
        for (Class elem : method.getParameterTypes()) {
            try {
                args.add(parseType(elem, ois));
            } catch (Exception err) {
                Main.logger.severe(String.format("Error to parse call argument: (%d) %s %s", elem.getName(), err, exceptionStacktraceToString(err)));
                args.add("DESER_FAILED_TO_PARSE");
                break;
            }
        }
        return args;
    }

    private boolean parseCall(long ack, byte []data) {
        boolean result = true;
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            ObjID id = ObjID.read(ois);
            int op = ois.readInt();
            long hash = ois.readLong();
            Main.logger.fine(String.format("JRMI Call: %s %d %d; ", id, op, hash));
            long tmp = (op == -1) ? hash : op;
            String remote_class = remote_interface_map_ext.get(id).getKey();
            Method remote_method = remote_interface_map_ext.get(id).getValue().get(tmp);
            if (remote_method == null) {
                Main.logger.severe(String.format("Error to parse call: can't found method %s %d", id, op));
                result = false;
            }
            List<Object> args = parseCallArguments(ack, remote_method, ois);
            String remote_args = args.toString();
            Main.output.info(String.format("JRMI call: %s.%s(%s)", remote_class, remote_method.getName().toString(), remote_args));
            Main.logger.fine(String.format("JRMI call: %s.%s(%s)", remote_class, remote_method.getName().toString(), remote_args));
            unanswered_calls.put(ack, remote_method);
        } catch (Exception err) {
            Main.logger.severe(String.format("Error to parse call: %d %s", ack, err));
            result = false;
        } catch (NoClassDefFoundError err) {
            Main.logger.severe(String.format("Error to parse call: ack", ack, err));
            result = false;
        }
        return result;
    }

    private boolean parseReturn(long seq, byte []data) {
        boolean result = true;
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            byte returnType = ois.readByte();
            UID.read(ois);
            Method remote_method = unanswered_calls.get(seq);
            if (remote_method == null) {
                Main.logger.info(String.format("Error: Unknown JRMI return for: %d", seq));
                return false;
            }
            Object obj = null;
            try {
                HackDGC hacked = new HackDGC();
                obj = parseType(remote_method.getReturnType(), ois);
                hacked.close();
            } catch (Exception err) {
                Main.logger.severe(String.format("Error to parse return type: (%d, %d) %s %s %s", seq, data.length, remote_method.getReturnType(), err, exceptionStacktraceToString(err)));
                obj = "DESER_FAILED_TO_PARSE";
                result = false;
            } catch (NoClassDefFoundError err) {
                Main.logger.severe(String.format("Error to parse return type: (%d, %d) %s %s", seq, data.length, remote_method.getReturnType(), err));
                obj = "DESER_FAILED_TO_PARSE";
                result = false;
            }
            String obj_info = (obj == null) ? "null" : obj.toString();
            Main.output.info(String.format("JRMI return for %s: %s", remote_method.getName().toString(), obj_info));
            Main.logger.fine(String.format("JRMI return for %s: %s", remote_method.getName().toString(), obj_info));
            ObjID remote_objid = null;
            Class remote_class = null;
            int remote_port = -1;
            if (obj instanceof Proxy) {
                remote_class = obj.getClass().getInterfaces()[1];
                Field field = Proxy.class.getDeclaredField("h");
                field.setAccessible(true);
                RemoteObjectInvocationHandler remote_invocation = (RemoteObjectInvocationHandler)field.get(obj);
                remote_objid = ((UnicastRef)remote_invocation.getRef()).getLiveRef().getObjID();
                remote_port = ((UnicastRef)remote_invocation.getRef()).getLiveRef().getPort();
            }
            if (obj instanceof RemoteObject) {
                RemoteObject remote_object = (RemoteObject) obj;
                remote_class = obj.getClass();
                remote_objid = ((UnicastRef) remote_object.getRef()).getLiveRef().getObjID();
                remote_port = ((UnicastRef) remote_object.getRef()).getLiveRef().getPort();
            }
            if (remote_objid != null && remote_class != null && remote_port != -1) {
                Map<Long, Method> methods = new HashMap<Long, Method>();
                for (Method elem : remote_class.getMethods()) {
                    methods.put(sun.rmi.server.Util.computeMethodHash(elem), elem);
                }
                remote_interface_map_ext.put(
                        remote_objid,
                        new AbstractMap.SimpleEntry<String, Map<Long, Method>>(
                                remote_class.getSimpleName(),
                                methods)
                );
                new_ports.add(remote_port);
            }
        } catch (Exception err) {
            Main.logger.severe(String.format("Error to parse return: %s %s", err.toString(), exceptionStacktraceToString(err)));
            result = false;
        }
        return result;
    }
    public static String exceptionStacktraceToString(Exception e)
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        e.printStackTrace(ps);
        ps.close();
        return baos.toString();
    }
}
public class Main {
    public static void disableWarning() {
        try {
            Field theUnsafe = Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            Unsafe u = (Unsafe) theUnsafe.get(null);

            Class cls = Class.forName("jdk.internal.module.IllegalAccessLogger");
            Field logger = cls.getDeclaredField("logger");
            u.putObjectVolatile(cls, u.staticFieldOffset(logger), null);
        } catch (Exception err) {
            logger.severe(String.format("Error in to disable warning in reflection: %s", err.toString()));
        }
    }

    static public void addJarToClasspath(String jarPath) {
        try {
            ClassLoader classLoader = ClassLoader.getSystemClassLoader();
            try {
                java.lang.reflect.Method method = classLoader.getClass().getDeclaredMethod("addURL", URL.class);
                method.setAccessible(true);
                method.invoke(classLoader, new File(jarPath).toURI().toURL());
            } catch (NoSuchMethodException e) {
                java.lang.reflect.Method method = classLoader.getClass().getDeclaredMethod("appendToClassPathForInstrumentation", String.class);
                method.setAccessible(true);
                method.invoke(classLoader, jarPath);
            }
        } catch (Exception err) {
            logger.severe(String.format("Error in adding jar to CLASSPATH: %s", err.toString()));
        }
    }
    static public void initializeRMILib(String libPath) {
        File dependencyDirectory = new File(libPath);
        File[] files = dependencyDirectory.listFiles();
        ArrayList<URL> urls = new ArrayList<URL>();
        for (int i = 0; i < files.length; i++) {
            if (files[i].getName().endsWith(".jar")) {
                String jarPath = files[i].getPath();
                logger.fine(String.format("Founded new JAR to load: %s", jarPath));
                addJarToClasspath(jarPath);
            }
        }
    }
    public static Logger logger, output;
    static public void initializeLogger(String logPath) {
        logger = Logger.getLogger("deser.logger");
        // disable console handler from root logger
        logger.setUseParentHandlers(false);
        logger.setLevel(Level.FINE);
        SimpleFormatter log_formatter = new SimpleFormatter() {
            private static final String format = "[%1$s] [%2$s] [%3$s] %4$s%n";

            @Override
            public synchronized String format(LogRecord lr) {
                return String.format(format,
                        lr.getLevel().getLocalizedName(),
                        lr.getSourceClassName(),
                        lr.getSourceMethodName(),
                        lr.getMessage()
                );
            }
        };
        ConsoleHandler log_conhandler = new ConsoleHandler();
        log_conhandler.setFormatter(log_formatter);
        log_conhandler.setLevel(Level.SEVERE);
        logger.addHandler(log_conhandler);
        try {
            FileHandler log_handler = new FileHandler(logPath);
            log_handler.setFormatter(log_formatter);
            logger.addHandler(log_handler);
        } catch (Exception err) {
            logger.severe(String.format("Error to create log handler: %s", err.toString()));
        }
    }
    static public void initializeOutput(String outputPath) {
        output = Logger.getLogger("deser.output");
        output.setUseParentHandlers(false);
        output.setLevel(Level.INFO);
        SimpleFormatter output_formatter = new SimpleFormatter() {
            private static final String format = "%1$s%n";
            @Override
            public synchronized String format(LogRecord lr) {
                return String.format(format,
                        lr.getMessage()
                );
            }
        };
        try {
            FileHandler output_handler = new FileHandler(outputPath);
            output_handler.setFormatter(output_formatter);
            output.addHandler(output_handler);
        } catch (Exception err) {
            logger.severe(String.format("Error to create log handler: %s", err.toString()));
        }
    }
    public static void deser(String pcapname, String rmipath, String logname, String outputname) {
        initializeLogger(logname);
        initializeOutput(outputname);
        disableWarning();
        initializeRMILib(rmipath);
        try {
            HashSet<Integer> process_ports = new HashSet<Integer>();
            process_ports.add(1099);
            Map<ObjID, AbstractMap.SimpleEntry<String, Map<Long, Method>>> remote_interface_map_ext = new HashMap<ObjID, AbstractMap.SimpleEntry<String, Map<Long, Method>>>();
            for (AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<ObjID, HashMap<String, Long>>> entry : Arrays.asList(
                    new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<ObjID, HashMap<String, Long>>>(
                            "java.rmi.registry.Registry",
                            new AbstractMap.SimpleEntry<ObjID, HashMap<String, Long>>(
                                    new ObjID(ObjID.REGISTRY_ID),
                                    new HashMap<String, Long>() {{
                                        put("bind", 0L);
                                        put("list", 1L);
                                        put("lookup", 2L);
                                        put("rebind", 3L);
                                        put("unbind", 4L);
                                    }}
                            )
                    ), new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<ObjID, HashMap<String, Long>>>(
                            "java.rmi.activation.Activator",
                            new AbstractMap.SimpleEntry<ObjID, HashMap<String, Long>>(
                                    new ObjID(ObjID.ACTIVATOR_ID),
                                    new HashMap<String, Long>() {{
                                    }}
                            )
                    ), new AbstractMap.SimpleEntry<String, AbstractMap.SimpleEntry<ObjID, HashMap<String, Long>>>(
                            "java.rmi.dgc.DGC",
                            new AbstractMap.SimpleEntry<ObjID, HashMap<String, Long>>(
                                    new ObjID(ObjID.DGC_ID),
                                    new HashMap<String, Long>() {{
                                        put("clean", 0L);
                                        put("dirty", 1L);
                                    }}
                            )
                    )
            )) {
                Class remote_interface = Class.forName(entry.getKey());
                Method[] methods = remote_interface.getMethods();
                HashMap<Long, Method> remote_interface_methods = new HashMap<Long, Method>();
                for (Method elem : remote_interface.getMethods()) {
                    remote_interface_methods.put(entry.getValue().getValue().get(elem.getName()), elem);
                }
                remote_interface_map_ext.put(
                        entry.getValue().getKey(), new AbstractMap.SimpleEntry<String, Map<Long, Method>>(entry.getKey(), remote_interface_methods)
                );
            }
            Pcap pcap = Pcap.openStream(pcapname);
            RMIParser parser = new RMIParser(remote_interface_map_ext);
            RMIHandler handler = new RMIHandler(parser, process_ports);
            pcap.loop(handler);
        } catch (Exception err) {
            logger.severe(String.format("Error during parsing pcap: %s", err.toString()));
        }
    }
    public static void main(String[] args) {
        deser("data//test.pcap", "data//rmilib", "data//test_deser.log", "data//test_output.log");
    }
}
