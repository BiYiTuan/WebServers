package com.webservers;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.TrustManagerFactory;

public class HttpsServer {

    private static SSLEngine sslEngine = null;
    private static SSLContext sslContext = null;
    private static final Integer port = 1500;
    private static ByteBuffer inputBuffer = ByteBuffer.allocate(4096);
    private static ByteBuffer outputBuffer = ByteBuffer.allocate(4096);
    private static final ByteBuffer networkBuffer = ByteBuffer.allocate(4096);
    private static Boolean handshakeComplete = false;
    private static boolean initialHSComplete = false;
    private static SSLEngineResult.HandshakeStatus initialHSStatus = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
    private static SSLEngineResult result;
    private static final Charset ascii = Charset.forName("US-ASCII");

    public static void main(String[] args) {
        long startTime = System.currentTimeMillis();
        try {
            final AsynchronousServerSocketChannel listener = AsynchronousServerSocketChannel.open().bind(new InetSocketAddress(port));
            listener.accept(null, new CompletionHandler<AsynchronousSocketChannel, Void>() {
                @Override
                public void completed(AsynchronousSocketChannel asynchronousSocketChannel, Void att) {
                    try {
                        listener.accept(null, this);
                        createSSLContext();

                        //Do Handshake
                        System.out.println("handshakeComplete: " + handshakeComplete);
                        sslEngine = sslContext.createSSLEngine();
                        sslEngine.setUseClientMode(false);
                        outputBuffer = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
                        outputBuffer.position(0);
                        outputBuffer.limit(0);
                        inputBuffer = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
                        while (!handshakeComplete) {
                            handshakeComplete = doHandshake(asynchronousSocketChannel);
                        }

                        //Read Request
                        read(asynchronousSocketChannel);

                        //Send Response
                        write(createResponse(), asynchronousSocketChannel);

                        asynchronousSocketChannel.close();
                    } catch (InterruptedException | ExecutionException | IOException | CertificateException | KeyManagementException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException ex) {
                        Logger.getLogger(HttpsServer.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                @Override
                public void failed(Throwable exc, Void att) {
                }
            });
        } catch (IOException ex) {
        }
        long endTime = System.currentTimeMillis();
        System.out.println("Https Server started in " + (endTime - startTime) + "ms.");
        while (true) {
            try {
                Thread.sleep(Long.MAX_VALUE);
            } catch (InterruptedException ex) {
            }
        }
    }

    private static void createSSLContext() throws CertificateException, IOException, KeyManagementException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
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

    private static ByteBuffer createResponse() {
        CharBuffer cb = CharBuffer.allocate(1024);
        for (;;) {
            try {
                cb.put("HTTP/1.0 ").put("200 OK").put("\r\n");
                cb.put("Server: niossl/0.1").put("\r\n");
                cb.put("Content-type: ").put("text/plain; charset=iso-8859-1").put("\r\n");
                cb.put("Content-length: ").put("31").put("\r\n");
                cb.put("\r\n");
                cb.put("bla bla bla bla");
                break;
            } catch (BufferOverflowException x) {
                cb = CharBuffer.allocate(cb.capacity() * 2);
            }
        }
        cb.flip();
        return ascii.encode(cb);
    }

    private static Boolean doHandshake(AsynchronousSocketChannel asynchronousSocketChannel) throws IOException, ExecutionException, InterruptedException, RuntimeException {
        if (initialHSComplete) {
            return initialHSComplete;
        }
        if (outputBuffer.hasRemaining()) {
            asynchronousSocketChannel.write(outputBuffer);
            if (outputBuffer.hasRemaining()) {
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
                if (asynchronousSocketChannel.read(inputBuffer).get() == -1) {
                    sslEngine.closeInbound();
                    return initialHSComplete;
                }
                needIO:
                while (initialHSStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    ByteBuffer bb2 = ByteBuffer.allocate(networkBuffer.limit());
                    inputBuffer.flip();
                    bb2.put(inputBuffer);
                    inputBuffer = bb2;
                    inputBuffer.flip();
                    result = sslEngine.unwrap(inputBuffer, networkBuffer);
                    inputBuffer.compact();
                    initialHSStatus = result.getHandshakeStatus();
                    switch (result.getStatus()) {
                        case OK:
                            switch (initialHSStatus) {
                                case NOT_HANDSHAKING:
                                case NEED_TASK:
                                    Runnable runnable;
                                    while ((runnable = sslEngine.getDelegatedTask()) != null) {
                                        runnable.run();
                                    }
                                    initialHSStatus = sslEngine.getHandshakeStatus();
                                    break;
                                case FINISHED:
                                    initialHSComplete = true;
                                    break needIO;
                            }
                            break;
                        case BUFFER_UNDERFLOW:
                            break needIO;
                        case BUFFER_OVERFLOW:
                            break;
                    }
                }
                if (initialHSStatus != SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    break;
                }
            case NEED_WRAP:
                outputBuffer.clear();
                result = sslEngine.wrap(ByteBuffer.allocate(0), outputBuffer);
                outputBuffer.flip();
                initialHSStatus = result.getHandshakeStatus();
                switch (result.getStatus()) {
                    case OK:
                        if (initialHSStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                            Runnable runnable;
                            while ((runnable = sslEngine.getDelegatedTask()) != null) {
                                runnable.run();
                            }
                            initialHSStatus = sslEngine.getHandshakeStatus();
                        }
                        if (initialHSComplete) {
                            write(ByteBuffer.allocate(0), asynchronousSocketChannel);
                        }
                        break;
                }
                break;
        }
        return initialHSComplete;
    }

    private static void read(AsynchronousSocketChannel asynchronousSocketChannel) throws IOException, ExecutionException, IllegalStateException, InterruptedException {
        SSLEngineResult result2;
        if (asynchronousSocketChannel.read(inputBuffer).get() == -1) {
            sslEngine.closeInbound();
        }
        do {
            ByteBuffer byteBuffer = ByteBuffer.allocate(networkBuffer.limit());
            inputBuffer.flip();
            byteBuffer.put(inputBuffer);
            inputBuffer = byteBuffer;
            inputBuffer.flip();
            result2 = sslEngine.unwrap(inputBuffer, networkBuffer);
            inputBuffer.compact();
            switch (result2.getStatus()) {
                case BUFFER_OVERFLOW:
                    break;
                case BUFFER_UNDERFLOW:
                    if (sslEngine.getSession().getPacketBufferSize() > inputBuffer.capacity()) {
                        byteBuffer = ByteBuffer.allocate(networkBuffer.limit());
                        outputBuffer.flip();
                        byteBuffer.put(outputBuffer);
                        outputBuffer = byteBuffer;
                        break;
                    }
                case OK:
                    if (result2.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                        Runnable runnable;
                        while ((runnable = sslEngine.getDelegatedTask()) != null) {
                            runnable.run();
                        }
                    }
                    break;
            }
        } while ((inputBuffer.position() != 0) && result2.getStatus() != SSLEngineResult.Status.BUFFER_UNDERFLOW);
    }

    private static void write(ByteBuffer src, AsynchronousSocketChannel asynchronousSocketChannel) throws IOException {
        asynchronousSocketChannel.write(outputBuffer);
        outputBuffer.clear();
        SSLEngineResult result2 = sslEngine.wrap(src, outputBuffer);
        outputBuffer.flip();
        switch (result2.getStatus()) {
            case OK:
                if (result2.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    Runnable runnable;
                    while ((runnable = sslEngine.getDelegatedTask()) != null) {
                        runnable.run();
                    }
                }
                break;
        }
        if (outputBuffer.hasRemaining()) {
            asynchronousSocketChannel.write(outputBuffer);
        }
    }
}
