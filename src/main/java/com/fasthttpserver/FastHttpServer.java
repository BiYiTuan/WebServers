package com.fasthttpserver;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public class FastHttpServer {

    private static final int port = 1500;

    public static void main(String[] args) {
        try {
            Long startTime = System.currentTimeMillis();
            AsynchronousChannelGroup group = AsynchronousChannelGroup.withThreadPool(Executors.newSingleThreadExecutor());
            final AsynchronousServerSocketChannel listener = AsynchronousServerSocketChannel.open(group).bind(new InetSocketAddress(port));
            AcceptCompletionHandler acceptCompletionHandler = new AcceptCompletionHandler(listener);
            SessionState state = new SessionState();
            listener.accept(state, acceptCompletionHandler);
            Long endTime = System.currentTimeMillis();
            System.out.println("Fast Http Server started in " + (endTime - startTime) + "ms.");
        } catch (IOException ex) {
        }

        while (true) {
            try {
                Thread.sleep(Long.MAX_VALUE);
            } catch (InterruptedException ex) {
            }
        }
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
        public void completed(AsynchronousSocketChannel socketChannel, SessionState sessionState) {
            SessionState newSessionState = new SessionState();
            listener.accept(newSessionState, this);
            ByteBuffer inputBuffer = ByteBuffer.allocate(2048);
            ReadCompletionHandler readCompletionHandler = new ReadCompletionHandler(socketChannel, inputBuffer);
            socketChannel.read(inputBuffer, sessionState, readCompletionHandler);
        }

        @Override
        public void failed(Throwable exc, SessionState sessionState) {
        }
    }

    private static class ReadCompletionHandler implements CompletionHandler<Integer, SessionState> {

        private final AsynchronousSocketChannel socketChannel;
        private final ByteBuffer inputBuffer;

        public ReadCompletionHandler(AsynchronousSocketChannel socketChannel, ByteBuffer inputBuffer) {
            this.socketChannel = socketChannel;
            this.inputBuffer = inputBuffer;
        }

        @Override
        public void completed(Integer bytesRead, SessionState sessionState) {
            //Request - Print request to console
            byte[] buffer = new byte[bytesRead];
            inputBuffer.rewind();
            inputBuffer.get(buffer);
            String message = new String(buffer);
            System.out.println("Received message from client : " + message);

            //Response - Print response to client (echo request to client)
            WriteCompletionHandler writeCompletionHandler = new WriteCompletionHandler(socketChannel);
            ByteBuffer outputBuffer = ByteBuffer.wrap(buffer);
            socketChannel.write(outputBuffer, sessionState, writeCompletionHandler);
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

}
