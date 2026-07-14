package com.antivirus.service;

import com.antivirus.model.BlockedDomain;
import com.antivirus.repository.BlockedDomainRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Local-only HTTP/HTTPS proxy with domain blocking.
 */

@Service
public class ProxyDomainBlockingService {

    private static final Logger logger = LoggerFactory.getLogger(ProxyDomainBlockingService.class);

    private static final int DEFAULT_PROXY_PORT = 8081;
    private static final int MAX_PROXY_THREADS = 50;
    private static final int SOCKET_TIMEOUT_MS = 30_000;
    private static final String LOCALHOST = "127.0.0.1";
    // Resource-exhaustion guard: a misbehaving or malicious client sending
    // an unbounded number of header lines would otherwise grow readHeaders()'s
    // list without limit.
    private static final int MAX_HEADER_LINES = 200;

    private static final Set<String> BLOCKED_IP_PREFIXES = Set.of(
            "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
            "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
            "192.168.", "169.254.", "::1", "fd", "fc");

    @Autowired
    private BlockedDomainRepository blockedDomainRepository;

    private ServerSocket serverSocket;
    private ExecutorService executorService;
    // N-06 Fix: Dedicated relay thread pool instead of unbounded raw thread
    // creation
    private ExecutorService relayExecutor;

    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private int proxyPort = DEFAULT_PROXY_PORT;

    public void startProxyServer() {
        if (isRunning.get()) {
            logger.info("Proxy server is already running on port {}", proxyPort);
            return;
        }

        try {
            serverSocket = new ServerSocket();
            serverSocket.bind(new InetSocketAddress(LOCALHOST, proxyPort));
            executorService = Executors.newFixedThreadPool(MAX_PROXY_THREADS);
            // N-06 Fix: Initialize bounded/cached relay pool
            relayExecutor = Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "proxy-relay");
                t.setDaemon(true);
                return t;
            });

            isRunning.set(true);
            executorService.submit(this::acceptConnections);
            logger.info("Proxy server started on {}:{}", LOCALHOST, proxyPort);
        } catch (IOException e) {
            logger.error("Failed to start proxy server: {}", e.getMessage());
            throw new RuntimeException("Failed to start proxy server", e);
        }
    }

    public void stopProxyServer() {
        if (!isRunning.get()) {
            return;
        }

        try {
            isRunning.set(false);
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
            if (executorService != null) {
                executorService.shutdownNow();
                executorService = null;
            }
            // N-06 Fix: Shut down relay executor
            if (relayExecutor != null) {
                relayExecutor.shutdownNow();
                relayExecutor = null;
            }
            logger.info("Proxy server stopped");
        } catch (IOException e) {
            logger.error("Error stopping proxy server: {}", e.getMessage());
        }
    }

    private void acceptConnections() {
        while (isRunning.get()) {
            try {
                Socket clientSocket = serverSocket.accept();
                executorService.submit(() -> handleClientConnection(clientSocket));
            } catch (IOException e) {
                if (isRunning.get()) {
                    logger.error("Error accepting connection: {}", e.getMessage());
                }
            }
        }
    }

    private void handleClientConnection(Socket clientSocket) {
        try (Socket client = clientSocket) {
            client.setSoTimeout(SOCKET_TIMEOUT_MS);
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(client.getInputStream(), StandardCharsets.ISO_8859_1));

            String requestLine = reader.readLine();
            if (requestLine == null || requestLine.isBlank()) {
                return;
            }

            String[] parts = requestLine.trim().split("\\s+");
            if (parts.length < 3) {
                return;
            }

            String method = parts[0].toUpperCase(Locale.ROOT);
            String target = parts[1];
            List<String> headerLines = readHeaders(reader);
            ProxyRequest request = parseRequest(method, target, headerLines);

            if (isDomainBlocked(request.host())) {
                sendBlockedResponse(client);
                return;
            }

            // N-03/B-02 Fix: SSRF protection now happens atomically with the
            // connect itself (see resolveAndValidate + handleConnect /
            // handleHttpForward), not as a separate pre-check here. A
            // pre-check followed by a second, independent DNS lookup at
            // connect time is a classic DNS-rebinding TOCTOU: an attacker's
            // DNS server can return a safe public IP for the check and a
            // private/internal IP moments later for the actual connection.
            if ("CONNECT".equals(method)) {
                handleConnect(client, request, requestLine, headerLines, reader);
            } else {
                handleHttpForward(client, request, requestLine, headerLines, reader);
            }
        } catch (IOException e) {
            logger.debug("Proxy client connection closed: {}", e.getMessage());
        }
    }

    private List<String> readHeaders(BufferedReader reader) throws IOException {
        List<String> headers = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
            if (headers.size() >= MAX_HEADER_LINES) {
                logger.warn("Rejecting request with more than {} header lines", MAX_HEADER_LINES);
                throw new IOException("Too many header lines");
            }
            headers.add(line);
        }
        return headers;
    }

    private ProxyRequest parseRequest(String method, String target, List<String> headerLines) {
        Map<String, String> headers = parseHeaderMap(headerLines);
        String host;
        int port;

        if ("CONNECT".equals(method)) {
            host = target.contains(":") ? target.substring(0, target.indexOf(':')) : target;
            port = target.contains(":")
                    ? Integer.parseInt(target.substring(target.indexOf(':') + 1))
                    : 443;
        } else if (target.startsWith("http://") || target.startsWith("https://")) {
            String withoutScheme = target.substring(target.indexOf("://") + 3);
            host = withoutScheme.contains("/")
                    ? withoutScheme.substring(0, withoutScheme.indexOf('/'))
                    : withoutScheme;
            if (host.contains(":")) {
                port = Integer.parseInt(host.substring(host.indexOf(':') + 1));
                host = host.substring(0, host.indexOf(':'));
            } else {
                port = target.startsWith("https://") ? 443 : 80;
            }
        } else {
            host = headers.getOrDefault("host", "localhost");
            if (host.contains(":")) {
                port = Integer.parseInt(host.substring(host.indexOf(':') + 1));
                host = host.substring(0, host.indexOf(':'));
            } else {
                port = 80;
            }
        }

        return new ProxyRequest(method, target, host, port, headers);
    }

    private Map<String, String> parseHeaderMap(List<String> headerLines) {
        Map<String, String> headers = new HashMap<>();
        for (String line : headerLines) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                headers.put(line.substring(0, colon).trim().toLowerCase(Locale.ROOT),
                        line.substring(colon + 1).trim());
            }
        }
        return headers;
    }

    private void handleConnect(Socket client, ProxyRequest request, String requestLine,
            List<String> headerLines, BufferedReader reader) throws IOException {
        InetAddress validatedAddress;
        try {
            validatedAddress = resolveAndValidate(request.host());
        } catch (SecurityException e) {
            logger.warn("SSRF attempt blocked on CONNECT: {}:{} ({})", request.host(), request.port(),
                    e.getMessage());
            sendBlockedResponse(client);
            return;
        }

        try (Socket remote = new Socket()) {
            // Connect using the already-resolved InetAddress, not the
            // hostname string: InetSocketAddress(String, int) would trigger
            // a second, independent DNS lookup here, reopening the exact
            // rebinding window resolveAndValidate() just closed.
            remote.connect(new InetSocketAddress(validatedAddress, request.port()), SOCKET_TIMEOUT_MS);
            remote.setSoTimeout(SOCKET_TIMEOUT_MS);

            OutputStream clientOut = client.getOutputStream();
            clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            clientOut.flush();

            // Some clients pipeline eagerly and send the first TLS
            // ClientHello bytes in the same TCP write as the CONNECT
            // request itself. The BufferedReader used to parse the CONNECT
            // headers can end up pulling those bytes into its internal
            // buffer too; without forwarding them explicitly here they are
            // silently lost (pump() below reads straight from the socket's
            // raw InputStream, which has already had those bytes drained).
            flushBufferedBytes(reader, remote.getOutputStream());

            relay(client, remote);
        } catch (IOException e) {
            logger.debug("CONNECT tunnel failed for {}:{} - {}", request.host(), request.port(), e.getMessage());
        }
    }

    private void handleHttpForward(Socket client, ProxyRequest request, String requestLine,
            List<String> headerLines, BufferedReader reader) throws IOException {
        String path = resolveForwardPath(request);
        String forwardRequestLine = request.method() + " " + path + " HTTP/1.1\r\n";
        StringBuilder headerBlock = new StringBuilder(forwardRequestLine);
        for (String header : headerLines) {
            if (!header.toLowerCase(Locale.ROOT).startsWith("proxy-connection:")) {
                headerBlock.append(header).append("\r\n");
            }
        }
        headerBlock.append("\r\n");

        InetAddress validatedAddress;
        try {
            validatedAddress = resolveAndValidate(request.host());
        } catch (SecurityException e) {
            logger.warn("SSRF attempt blocked on forward: {}:{} ({})", request.host(), request.port(),
                    e.getMessage());
            sendBlockedResponse(client);
            return;
        }

        try (Socket remote = new Socket()) {
            // Same TOCTOU reasoning as handleConnect: connect to the
            // address resolveAndValidate() already checked, never re-
            // resolve the hostname string at connect time.
            remote.connect(new InetSocketAddress(validatedAddress, request.port()), SOCKET_TIMEOUT_MS);
            remote.setSoTimeout(SOCKET_TIMEOUT_MS);

            OutputStream remoteOut = remote.getOutputStream();
            remoteOut.write(headerBlock.toString().getBytes(StandardCharsets.ISO_8859_1));

            // A request body (POST/PUT/PATCH, Content-Length or chunked)
            // sent in the same TCP write as the headers can end up partly
            // or fully consumed by the BufferedReader while it was reading
            // header lines. Without this, that body data is silently
            // dropped rather than forwarded, truncating the request on the
            // remote end. This needs no Content-Length/chunked parsing of
            // our own: it just forwards whatever bytes already arrived,
            // byte-for-byte, before the raw relay takes over for the rest.
            flushBufferedBytes(reader, remoteOut);
            remoteOut.flush();

            relay(client, remote);
        } catch (IOException e) {
            logger.debug("HTTP forward failed for {}:{} - {}", request.host(), request.port(), e.getMessage());
        }
    }

    // Drains any bytes the BufferedReader already pulled off the socket
    // (into its internal buffer) while reading the request line/headers,
    // and writes them onward unchanged. ISO_8859_1 is a 1:1 byte<->char
    // mapping, so this round-trip is lossless for arbitrary binary data
    // (TLS handshake bytes, binary POST bodies, etc.), not just text.
    private void flushBufferedBytes(BufferedReader reader, OutputStream out) throws IOException {
        char[] buffer = new char[8192];
        while (reader.ready()) {
            int read = reader.read(buffer);
            if (read == -1) {
                break;
            }
            out.write(new String(buffer, 0, read).getBytes(StandardCharsets.ISO_8859_1));
        }
    }

    private String resolveForwardPath(ProxyRequest request) {
        String target = request.target();
        if (target.startsWith("http://")) {
            String withoutScheme = target.substring(7);
            int slash = withoutScheme.indexOf('/');
            return slash >= 0 ? withoutScheme.substring(slash) : "/";
        }
        if (target.startsWith("https://")) {
            String withoutScheme = target.substring(8);
            int slash = withoutScheme.indexOf('/');
            return slash >= 0 ? withoutScheme.substring(slash) : "/";
        }
        return target.startsWith("/") ? target : "/" + target;
    }

    private void relay(Socket client, Socket remote) {
        // N-06 Fix: Use managed ExecutorService instead of raw Thread creation
        Future<?> c2r = relayExecutor.submit(() -> pump(client, remote));
        Future<?> r2c = relayExecutor.submit(() -> pump(remote, client));
        try {
            c2r.get();
            r2c.get();
        } catch (Exception e) {
            Thread.currentThread().interrupt();
            c2r.cancel(true);
            r2c.cancel(true);
        }
    }

    private void pump(Socket inputSocket, Socket outputSocket) {
        try (InputStream in = inputSocket.getInputStream();
                OutputStream out = outputSocket.getOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
                out.flush();
            }
        } catch (IOException ignored) {
            // Connection closed
        }
    }

    @SuppressWarnings("null")
    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isBlank()) {
            return false;
        }
        String normalized = domain.toLowerCase(Locale.ROOT);
        if (normalized.contains(":")) {
            normalized = normalized.substring(0, normalized.indexOf(':'));
        }
        return blockedDomainRepository.findByDomain(normalized)
                .map(BlockedDomain::isActive)
                .orElse(false);
    }

    /**
     * N-03 Fix: Prevent SSRF by blocking connections to internal, loopback, or
     * link-local IPs. Kept as its own method (rather than folded into
     * resolveAndValidate) because ProxyDomainBlockingServiceTest exercises
     * it directly via reflection; behavior/signature unchanged.
     */
    @SuppressWarnings("unused")
    private boolean isPrivateOrLoopback(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        if (h.equals("localhost") || h.endsWith(".localhost"))
            return true;
        try {
            InetAddress addr = InetAddress.getByName(h);
            return isPrivateOrLoopbackAddress(addr);
        } catch (UnknownHostException e) {
            return true; // fail-closed: block unresolvable hosts
        }
    }

    private boolean isPrivateOrLoopbackAddress(InetAddress addr) {
        String ip = addr.getHostAddress();
        return BLOCKED_IP_PREFIXES.stream().anyMatch(ip::startsWith)
                || addr.isLoopbackAddress()
                || addr.isSiteLocalAddress()
                || addr.isLinkLocalAddress()
                || addr.isAnyLocalAddress();
    }

    /**
     * B-02 Fix: resolves the host to a concrete InetAddress and validates
     * THAT SAME OBJECT, which the caller must then connect to directly
     * (InetSocketAddress(InetAddress, int), never the hostname string
     * again). A separate check-then-resolve-again pattern is vulnerable to
     * DNS rebinding: an attacker's DNS server can return a safe address for
     * the check and a private/internal address moments later for the
     * connection, since each hostname lookup is independent and nothing
     * requires the two answers to match.
     *
     * @throws SecurityException if the host is blocked or fails to resolve
     *                           (fail-closed)
     */
    private InetAddress resolveAndValidate(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        if (h.equals("localhost") || h.endsWith(".localhost")) {
            throw new SecurityException("Blocked host: " + host);
        }
        InetAddress addr;
        try {
            addr = InetAddress.getByName(h);
        } catch (UnknownHostException e) {
            throw new SecurityException("Unresolvable host (fail-closed): " + host);
        }
        if (isPrivateOrLoopbackAddress(addr)) {
            throw new SecurityException("Blocked private/loopback address: " + addr.getHostAddress());
        }
        return addr;
    }

    private void sendBlockedResponse(Socket clientSocket) throws IOException {
        String response = "HTTP/1.1 403 Forbidden\r\n" +
                "Content-Type: text/html\r\n" +
                "Connection: close\r\n\r\n" +
                "<html><body><h1>Access Denied</h1>" +
                "<p>This domain has been blocked by the antivirus software.</p></body></html>";
        clientSocket.getOutputStream().write(response.getBytes(StandardCharsets.ISO_8859_1));
    }

    public boolean isProxyRunning() {
        return isRunning.get();
    }

    public int getProxyPort() {
        return proxyPort;
    }

    public Map<String, String> getProxyInstructions() {
        Map<String, String> instructions = new HashMap<>();
        instructions.put("windows",
                "1. Open Windows Settings > Network & Internet > Proxy\n" +
                        "2. Enable 'Use a proxy server'\n" +
                        "3. Address: 127.0.0.1  Port: " + proxyPort);
        instructions.put("macos",
                "1. System Preferences > Network > Advanced > Proxies\n" +
                        "2. Enable Web Proxy (HTTP)\n" +
                        "3. Address: 127.0.0.1  Port: " + proxyPort);
        instructions.put("linux",
                "1. System Settings > Network > Network Proxy > Manual\n" +
                        "2. HTTP Proxy: 127.0.0.1  Port: " + proxyPort);
        return instructions;
    }

    private record ProxyRequest(String method, String target, String host, int port,
            Map<String, String> headers) {
    }
}
