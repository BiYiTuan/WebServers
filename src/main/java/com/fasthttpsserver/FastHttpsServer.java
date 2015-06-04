package com.fasthttpsserver;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;

public class FastHttpsServer {

    private static final int port = 1500;
    private static SSLContext sslContext;

    public static void main(String[] args) {
        try {
            long startTime = System.currentTimeMillis();
            createSSLContext();
            AsynchronousChannelGroup group = AsynchronousChannelGroup.withThreadPool(Executors.newSingleThreadExecutor());
            final AsynchronousServerSocketChannel listener = AsynchronousServerSocketChannel.open(group).bind(new InetSocketAddress(port));
            AcceptCompletionHandler acceptCompletionHandler = new AcceptCompletionHandler(listener);
            SessionState state = new SessionState();
            listener.accept(state, acceptCompletionHandler);
            long endTime = System.currentTimeMillis();
            System.out.println("Fast Https Server started in " + (endTime - startTime) + "ms.");
        } catch (IOException ex) {
            Logger.getLogger(FastHttpsServer.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(FastHttpsServer.class.getName()).log(Level.SEVERE, null, ex);
        }

        while (true) {
            try {
                Thread.sleep(Long.MAX_VALUE);
            } catch (InterruptedException ex) {
            }
        }
    }

    private static void createSSLContext() throws Exception {
        char[] passphrase = "password".toCharArray();
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("keystore.jks"), passphrase);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, passphrase);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ks);
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    }

    private static class SessionState {

        private final Map<String, String> sessionProps = new ConcurrentHashMap<>();

        public String getProperty(String key) {
            return sessionProps.get(key);
        }

        public void setProperty(String key, String value) {
            sessionProps.put(key, value);
        }
    }

    private static class AcceptCompletionHandler implements CompletionHandler<AsynchronousSocketChannel, SessionState> {

        private final AsynchronousServerSocketChannel listener;

        public AcceptCompletionHandler(AsynchronousServerSocketChannel listener) {
            this.listener = listener;
        }

        @Override
        public void completed(AsynchronousSocketChannel asynchronousSocketChannel, SessionState sessionState) {
            SessionState newSessionState = new SessionState();
            listener.accept(newSessionState, this);
            ByteBuffer inputBuffer = ByteBuffer.allocate(2048);
            ReadCompletionHandler readCompletionHandler = new ReadCompletionHandler(asynchronousSocketChannel, inputBuffer);
            asynchronousSocketChannel.read(inputBuffer, sessionState, readCompletionHandler);
        }

        @Override
        public void failed(Throwable exc, SessionState sessionState) {
        }
    }

    private static class ReadCompletionHandler implements CompletionHandler<Integer, SessionState> {

        private AsynchronousSocketChannel asynchronousSocketChannel;
        private ByteBuffer inputBuffer;

        public ReadCompletionHandler(AsynchronousSocketChannel asynchronousSocketChannel, ByteBuffer inputBuffer) {
            try {
                this.asynchronousSocketChannel = asynchronousSocketChannel;
                this.inputBuffer = inputBuffer;
                RequestHandler requestHandler = new RequestHandler(asynchronousSocketChannel, sslContext);
                requestHandler.handle();
            } catch (Exception ex) {
                Logger.getLogger(FastHttpsServer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        @Override
        public void completed(Integer bytesRead, SessionState sessionState) {
            try {
                //Request - Print request to console
                byte[] buffer = new byte[bytesRead];
                inputBuffer.rewind();
                inputBuffer.get(buffer);
                String message = new String(buffer);
                System.out.println("Received message from client : " + message);

                //Response - Print response to client (echo request to client)
                WriteCompletionHandler writeCompletionHandler = new WriteCompletionHandler(asynchronousSocketChannel);
                ByteBuffer outputBuffer = ByteBuffer.wrap(buffer);
                asynchronousSocketChannel.write(outputBuffer, sessionState, writeCompletionHandler);
            } catch (Exception ex) {
                Logger.getLogger(FastHttpsServer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        @Override
        public void failed(Throwable exc, SessionState attachment) {
        }
    }

    private static class WriteCompletionHandler implements CompletionHandler<Integer, SessionState> {

        private final AsynchronousSocketChannel socketChannel;

        public WriteCompletionHandler(AsynchronousSocketChannel socketChannel) {
            this.socketChannel = socketChannel;
        }

        @Override
        public void completed(Integer bytesWritten, SessionState attachment) {
            try {
                socketChannel.close();
            } catch (IOException ex) {
            }
        }

        @Override
        public void failed(Throwable exc, SessionState attachment) {

        }
    }

    private static class RequestHandler {

        private ByteBuffer rbb = null;
        private Boolean requestReceived = false;
        private Request request = null;
        private static int created = 0;
        private static SSLEngine sslEngine = null;
        private final AsynchronousSocketChannel sc;
        private static ByteBuffer requestBB;
        private static int appBBSize;
        private static int netBBSize;
        private static ByteBuffer inNetBB;
        private static ByteBuffer outNetBB;
        private static final ByteBuffer hsBB = ByteBuffer.allocate(0);
        private final ByteBuffer fileChannelBB = null;
        private static SSLEngineResult.HandshakeStatus initialHSStatus;
        private static boolean initialHSComplete;
        private boolean shutdown = false;
        private Code code;
        private boolean headersOnly;
        private static final String CRLF = "\r\n";
        private static final Charset ascii = Charset.forName("US-ASCII");
        private ByteBuffer hbb = null;
        private String type;
        private String content2;
        private ByteBuffer bb = null;

        public RequestHandler(AsynchronousSocketChannel asynchronousSocketChannel, SSLContext sslc) throws IOException {
            synchronized (RequestHandler.class) {
                created++;
                if ((created % 50) == 0) {
                    System.out.println(".");
                    created = 0;
                } else {
                    System.out.print(".");
                }
            }
            this.sc = asynchronousSocketChannel;
            sslEngine = sslc.createSSLEngine();
            sslEngine.setUseClientMode(false);
            initialHSStatus = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
            initialHSComplete = false;
            netBBSize = sslEngine.getSession().getPacketBufferSize();
            inNetBB = ByteBuffer.allocate(netBBSize);
            outNetBB = ByteBuffer.allocate(netBBSize);
            outNetBB.position(0);
            outNetBB.limit(0);
            appBBSize = sslEngine.getSession().getApplicationBufferSize();
            requestBB = ByteBuffer.allocate(appBBSize);
        }

        private boolean receive() throws IOException, InterruptedException, ExecutionException {
            if (requestReceived) {
                return true;
            }
            if (!doHandshake()) {
                return false;
            }
            if ((read() < 0) || isComplete(getReadBuf())) {
                rbb = getReadBuf();
                return (requestReceived = true);
            }
            return false;
        }

        private static boolean isComplete(ByteBuffer bb) {
            int p = bb.position() - 4;
            if (p < 0) {
                return false;
            }
            return (((bb.get(p + 0) == '\r') && (bb.get(p + 1) == '\n') && (bb.get(p + 2) == '\r') && (bb.get(p + 3) == '\n')));
        }

        private boolean parse() throws IOException, Exception {
            try {
                request = Request.parse(rbb);
                return true;
            } catch (Exception x) {
                Response(Code.BAD_REQUEST, x.getMessage(), null);
            }
            return false;
        }

        private void build() throws IOException {
            Request.Action action = request.action();
            if ((action != Request.Action.GET) && (action != Request.Action.HEAD)) {
                Response(Code.METHOD_NOT_ALLOWED, request.toString(), null);
            }
            Response(Code.OK, request.toString(), action);
        }

        private void Content(CharSequence c, String t) {
            content2 = c.toString();
            if (!content2.endsWith("\n")) {
                content2 += "\n";
            }
            type = t + "; charset=iso-8859-1";
        }

        private void Content(CharSequence c) {
            Content(c, "text/plain");
        }

        private void Content(Exception x) {
            StringWriter sw = new StringWriter();
            x.printStackTrace(new PrintWriter(sw));
            type = "text/plain; charset=iso-8859-1";
            content2 = sw.toString();
        }

        private String type() {
            return type;
        }

        private boolean send() throws IOException {
            try {
                return send2(this);
            } catch (IOException x) {
                if (x.getMessage().startsWith("Resource temporarily")) {
                    System.err.println("## RTA");
                    return true;
                }
                throw x;
            }
        }

        public boolean send2(RequestHandler requestHandler) throws IOException {
            if (hbb == null) {
                throw new IllegalStateException();
            }
            if (hbb.hasRemaining()) {
                if (requestHandler.write(hbb) <= 0) {
                    return true;
                }
            }
            if (!headersOnly) {
                if (send3(requestHandler)) {
                    return true;
                }
            }
            return !requestHandler.dataFlush();
        }

        private boolean send3(RequestHandler requestHandler) throws IOException {
            if (bb == null) {
                throw new IllegalStateException();
            }
            requestHandler.write(bb);
            return bb.hasRemaining();
        }

        private ByteBuffer headers() {
            CharBuffer cb = CharBuffer.allocate(1024);
            for (;;) {
                try {
                    cb.put("HTTP/1.0 ").put(code.toString()).put(CRLF);
                    cb.put("Server: niossl/0.1").put(CRLF);
                    cb.put("Content-type: ").put(type()).put(CRLF);
                    cb.put("Content-length: ").put(Long.toString(length())).put(CRLF);
                    cb.put(CRLF);
                    break;
                } catch (BufferOverflowException x) {
                    cb = CharBuffer.allocate(cb.capacity() * 2);
                }
            }
            cb.flip();
            return ascii.encode(cb);
        }

        public void prepare() throws IOException {
            prepare2();
            hbb = headers();
        }

        private void encode() {
            if (bb == null) {
                bb = ascii.encode(CharBuffer.wrap(content2));
            }
        }

        private long length() {
            encode();
            return bb.remaining();
        }

        private void prepare2() {
            encode();
            bb.rewind();
        }

        public void Response(Code rc, String c, Request.Action head) {
            code = rc;
            content2 = c;
            headersOnly = (head == Request.Action.HEAD);
        }

        public void handle() throws IOException, Exception {
            try {
                if (request == null) {
                    if (!receive()) {
                        return;
                    }
                    rbb.flip();
                    if (parse()) {
                        build();
                    }
                    try {
                        prepare();
                    } catch (IOException x) {
                        Response(Code.NOT_FOUND, x.getMessage(), null);
                        prepare();
                    }
                    if (!send()) {
                        if (shutdown()) {
                            close();
                        }
                    }
                } else {
                    if (!send()) {
                        if (shutdown()) {
                            close();
                        }
                    }
                }
            } catch (IOException ex) {
                String m = ex.getMessage();
                if (!m.equals("Broken pipe") && !m.equals("Connection reset by peer")) {
                    System.err.println("RequestHandler: " + ex.toString());
                }
                try {
                    shutdown();
                } catch (IOException e) {
                }
                close();
            }

        }

        void close() throws IOException {
            sc.close();
        }

        private ByteBuffer getReadBuf() {
            return requestBB;
        }

        private void resizeRequestBB() {
            if (requestBB.remaining() < appBBSize) {
                ByteBuffer bb2 = ByteBuffer.allocate(requestBB.capacity() * 2);
                requestBB.flip();
                bb2.put(requestBB);
                requestBB = bb2;
            }
        }

        private void resizeResponseBB() {
            ByteBuffer bb3 = ByteBuffer.allocate(netBBSize);
            inNetBB.flip();
            bb3.put(inNetBB);
            inNetBB = bb3;
        }

        private boolean tryFlush(ByteBuffer bb) throws IOException {
            sc.write(bb);
            return !bb.hasRemaining();
        }

        private boolean doHandshake() throws IOException, InterruptedException, ExecutionException {
            SSLEngineResult result;
            if (initialHSComplete) {
                return initialHSComplete;
            }
            System.out.println("outNetBB: " + outNetBB.toString());
            if (outNetBB.hasRemaining()) {
                if (!tryFlush(outNetBB)) {
                    return false;
                }
                switch (initialHSStatus) {
                    case FINISHED:
                        initialHSComplete = true;
                    case NEED_UNWRAP:
                        break;
                }
                return initialHSComplete;
            }
            switch (initialHSStatus) {
                case NEED_UNWRAP:
                    int result2 = sc.read(inNetBB).get();
                    System.out.println("result: " + result2);
                    if (sc.read(inNetBB).get() == -1) {
                        System.out.println("Close inbound");
                        sslEngine.closeInbound();
                        return initialHSComplete;
                    }
                    needIO:
                    while (initialHSStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                        resizeRequestBB();
                        inNetBB.flip();
                        result = sslEngine.unwrap(inNetBB, requestBB);
                        inNetBB.compact();
                        initialHSStatus = result.getHandshakeStatus();
                        switch (result.getStatus()) {
                            case OK:
                                switch (initialHSStatus) {
                                    case NOT_HANDSHAKING:
                                        throw new IOException("Not handshaking during initial handshake");
                                    case NEED_TASK:
                                        initialHSStatus = doTasks();
                                        break;
                                    case FINISHED:
                                        initialHSComplete = true;
                                        break needIO;
                                }
                                break;
                            case BUFFER_UNDERFLOW:
                                netBBSize = sslEngine.getSession().getPacketBufferSize();
                                if (netBBSize > inNetBB.capacity()) {
                                    resizeResponseBB();
                                }
                                break needIO;
                            case BUFFER_OVERFLOW:
                                appBBSize = sslEngine.getSession().getApplicationBufferSize();
                                break;
                            default:
                                throw new IOException("Received" + result.getStatus() + "during initial handshaking");
                        }
                    }
                    if (initialHSStatus != SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                        break;
                    }
                case NEED_WRAP:
                    outNetBB.clear();
                    result = sslEngine.wrap(hsBB, outNetBB);
                    outNetBB.flip();
                    initialHSStatus = result.getHandshakeStatus();
                    switch (result.getStatus()) {
                        case OK:
                            if (initialHSStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                                initialHSStatus = doTasks();
                            }
                            break;
                        default:
                            throw new IOException("Received" + result.getStatus() + "during initial handshaking");
                    }
                    break;
                default:
                    throw new RuntimeException("Invalid Handshaking State" + initialHSStatus);
            }
            return initialHSComplete;
        }

        private SSLEngineResult.HandshakeStatus doTasks() {
            Runnable runnable;
            while ((runnable = sslEngine.getDelegatedTask()) != null) {
                runnable.run();
            }
            return sslEngine.getHandshakeStatus();
        }

        private int read() throws IOException, InterruptedException, ExecutionException {
            SSLEngineResult result;
            if (!initialHSComplete) {
                throw new IllegalStateException();
            }
            int pos = requestBB.position();
            if (sc.read(inNetBB).get() == -1) {
                sslEngine.closeInbound();
                return -1;
            }
            do {
                resizeRequestBB();
                inNetBB.flip();
                result = sslEngine.unwrap(inNetBB, requestBB);
                inNetBB.compact();
                switch (result.getStatus()) {
                    case BUFFER_OVERFLOW:
                        appBBSize = sslEngine.getSession().getApplicationBufferSize();
                        break;
                    case BUFFER_UNDERFLOW:
                        netBBSize = sslEngine.getSession().getPacketBufferSize();
                        if (netBBSize > inNetBB.capacity()) {
                            resizeResponseBB();
                            break;
                        }
                    case OK:
                        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                            doTasks();
                        }
                        break;
                    default:
                        throw new IOException("sslEngine error during data read: " + result.getStatus());
                }
            } while ((inNetBB.position() != 0) && result.getStatus() != SSLEngineResult.Status.BUFFER_UNDERFLOW);
            return (requestBB.position() - pos);
        }

        private int write(ByteBuffer src) throws IOException {
            if (!initialHSComplete) {
                throw new IllegalStateException();
            }
            int retValue = 0;
            if (outNetBB.hasRemaining() && !tryFlush(outNetBB)) {
                return retValue;
            }
            outNetBB.clear();
            SSLEngineResult result = sslEngine.wrap(src, outNetBB);
            retValue = result.bytesConsumed();
            outNetBB.flip();
            switch (result.getStatus()) {
                case OK:
                    if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                        doTasks();
                    }
                    break;
                default:
                    throw new IOException("sslEngine error during data write: " + result.getStatus());
            }
            if (outNetBB.hasRemaining()) {
                tryFlush(outNetBB);
            }
            return retValue;
        }

        boolean dataFlush() throws IOException {
            boolean fileFlushed = true;
            if ((fileChannelBB != null) && fileChannelBB.hasRemaining()) {
                write(fileChannelBB);
                fileFlushed = !fileChannelBB.hasRemaining();
            } else if (outNetBB.hasRemaining()) {
                tryFlush(outNetBB);
            }
            return (fileFlushed && !outNetBB.hasRemaining());
        }

        boolean shutdown() throws IOException {
            if (!shutdown) {
                sslEngine.closeOutbound();
                shutdown = true;
            }
            if (outNetBB.hasRemaining() && tryFlush(outNetBB)) {
                return false;
            }
            outNetBB.clear();
            SSLEngineResult result = sslEngine.wrap(hsBB, outNetBB);
            if (result.getStatus() != SSLEngineResult.Status.CLOSED) {
                throw new SSLException("Improper close state");
            }
            outNetBB.flip();
            if (outNetBB.hasRemaining()) {
                tryFlush(outNetBB);
            }
            return (!outNetBB.hasRemaining() && (result.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NEED_WRAP));
        }

        static class Code {

            private final int number;
            private final String reason;
            static Code OK = new Code(200, "OK");
            static Code BAD_REQUEST = new Code(400, "Bad Request");
            static Code NOT_FOUND = new Code(404, "Not Found");
            static Code METHOD_NOT_ALLOWED = new Code(405, "Method Not Allowed");

            private Code(int i, String r) {
                number = i;
                reason = r;
            }

            @Override
            public String toString() {
                return number + " " + reason;
            }

        }
    }

    private static class Request {

        private final Action action;
        private final String version;
        private final URI uri;
        private static final Charset ascii = Charset.forName("US-ASCII");
        private static final Pattern requestPattern = Pattern.compile("\\A([A-Z]+) +([^ ]+) +HTTP/([0-9\\.]+)$" + ".*^Host: ([^ ]+)$.*\r\n\r\n\\z", Pattern.MULTILINE | Pattern.DOTALL);

        private Request(Action a, String v, URI u) {
            action = a;
            version = v;
            uri = u;
        }

        private static class Action {

            public String name;
            public static Action GET = new Action("GET");
            public static Action PUT = new Action("PUT");
            public static Action POST = new Action("POST");
            public static Action HEAD = new Action("HEAD");

            private Action(String name) {
                this.name = name;
            }

            @Override
            public String toString() {
                return name;
            }

            private static Action parse(String s) {
                if (s.equals("GET")) {
                    return GET;
                }
                if (s.equals("PUT")) {
                    return PUT;
                }
                if (s.equals("POST")) {
                    return POST;
                }
                if (s.equals("HEAD")) {
                    return HEAD;
                }
                throw new IllegalArgumentException(s);
            }
        }

        private Action action() {
            return action;
        }

        @Override
        public String toString() {
            return (action + " " + version + " " + uri);
        }

        private static Request parse(ByteBuffer bb) throws Exception {
            CharBuffer cb = ascii.decode(bb);
            Matcher m = requestPattern.matcher(cb);
            if (!m.matches()) {
                throw new Exception("MalformedRequestException");
            }
            Action a;
            try {
                a = Action.parse(m.group(1));
            } catch (IllegalArgumentException x) {
                throw new Exception("MalformedRequestException");
            }
            URI u;
            try {
                u = new URI("http://" + m.group(4) + m.group(2));
            } catch (URISyntaxException x) {
                throw new Exception("MalformedRequestException");
            }
            return new Request(a, m.group(3), u);
        }
    }

}
