package org.example.pcaptest.core;

import lombok.extern.slf4j.Slf4j;
import org.example.pcaptest.core.entity.HttpRequestData;
import org.example.pcaptest.core.entity.HttpResponseData;
import org.example.pcaptest.core.entity.SimplePacketInfo;
import org.example.pcaptest.core.interceptor.HttpPacketInterceptor;
import org.example.pcaptest.core.util.HttpHeaderUtils;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

@Slf4j
public class HttpPacketListener implements PacketListener {

    // 存储HTTP请求流（线程安全）
    private final Map<String, SortedMap<Long, byte[]>> httpRequestStreams = new ConcurrentHashMap<>();
    // 存储HTTP响应流（线程安全）
    private final Map<String, SortedMap<Long, byte[]>> httpResponseStreams = new ConcurrentHashMap<>();

    // 存储每个流的预期下一个序列号（线程安全）
    private final Map<String, Long> requestExpectedSeq = new ConcurrentHashMap<>();
    private final Map<String, Long> responseExpectedSeq = new ConcurrentHashMap<>();

    // 记录流最后活动时间（用于超时清理）
    private final Map<String, Long> requestLastActiveTime = new ConcurrentHashMap<>();
    private final Map<String, Long> responseLastActiveTime = new ConcurrentHashMap<>();

    // 流的预期总长度和当前已接收长度
    private final Map<String, Integer> responseExpectedLength = new ConcurrentHashMap<>();
    private final Map<String, Integer> responseCurrentLength = new ConcurrentHashMap<>();

    // 记录单个请求/响应是否已处理（键为请求唯一ID）
    private final Map<String, Boolean> singleRequestProcessed = new ConcurrentHashMap<>();
    private final Map<String, Boolean> singleResponseProcessed = new ConcurrentHashMap<>();

    // 存储HTTP流的StreamKey
    private final Set<String> httpStreams = ConcurrentHashMap.newKeySet();

    // 定时清理超时流的调度器（多线程优化）
    private final ScheduledExecutorService scheduler;

    private final List<HttpPacketInterceptor> interceptors;

    // 多线程处理核心：线程池+按流绑定的任务队列
    private final int processPoolSize;
    private final ExecutorService processPool;
    private final List<BlockingQueue<Runnable>> streamQueues;

    public HttpPacketListener(List<HttpPacketInterceptor> interceptors) {
        this.interceptors = interceptors;
        // 线程池大小设为CPU核心数，充分利用多核性能
        this.processPoolSize = Runtime.getRuntime().availableProcessors();
        this.streamQueues = new ArrayList<>(processPoolSize);
        // 为每个线程创建独立队列（保证同一流的包顺序执行）
        for (int i = 0; i < processPoolSize; i++) {
            streamQueues.add(new LinkedBlockingQueue<>());
        }
        // 自定义线程池，绑定队列与线程
        this.processPool = new ThreadPoolExecutor(
                processPoolSize,
                processPoolSize,
                0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(),
                new StreamThreadFactory()
        );
        // 启动队列消费线程
        startQueueConsumers();

        // 定时清理线程池改为2线程（避免单线程瓶颈）
        this.scheduler = Executors.newScheduledThreadPool(2);
        // 每10秒清理一次30秒无活动的流
        this.scheduler.scheduleAtFixedRate(this::cleanupExpiredStreams, 0, 10, TimeUnit.SECONDS);
    }

    // 启动队列消费线程，每个线程负责一个队列
    private void startQueueConsumers() {
        for (int i = 0; i < processPoolSize; i++) {
            final int queueIndex = i;
            processPool.submit(() -> {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        // 从对应队列获取任务并执行
                        Runnable task = streamQueues.get(queueIndex).take();
                        task.run();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    } catch (Exception e) {
                        log.error("处理队列任务时出错", e);
                    }
                }
            });
        }
    }

    @Override
    public void gotPacket(Packet packet) {
        // 解析IP和TCP层
        IpV4Packet ipV4 = packet.get(IpV4Packet.class);
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (ipV4 == null || tcp == null) return;

        // 提取基础信息
        TcpPacket.TcpHeader tcpHeader = tcp.getHeader();
        String srcIp = ipV4.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipV4.getHeader().getDstAddr().getHostAddress();
        int srcPort = tcpHeader.getSrcPort().valueAsInt();
        int dstPort = tcpHeader.getDstPort().valueAsInt();

        // 生成流标识
        String streamKey = buildStreamKey(srcIp, srcPort, dstIp, dstPort);
        String reverseStreamKey = buildStreamKey(dstIp, dstPort, srcIp, srcPort);

        byte[] payload = tcp.getPayload() != null ? tcp.getPayload().getRawData() : new byte[0];

        // 只在新流第一个有payload的包做HTTP判断
        if (!httpStreams.contains(streamKey) && !httpStreams.contains(reverseStreamKey)) {
            if (payload.length > 0) {
                String payloadStr = new String(payload, StandardCharsets.US_ASCII);
                boolean isHttp = payloadStr.startsWith("GET ") ||
                        payloadStr.startsWith("POST ") ||
                        payloadStr.startsWith("HEAD ") ||
                        payloadStr.startsWith("PUT ") ||
                        payloadStr.startsWith("DELETE ") ||
                        payloadStr.startsWith("OPTIONS ") ||
                        payloadStr.startsWith("PATCH ") ||
                        payloadStr.startsWith("HTTP/");

                if (isHttp) {
                    // 标记双向流为HTTP
                    httpStreams.add(streamKey);
                    httpStreams.add(reverseStreamKey);
                    log.info("[HTTP] 发现HTTP流: {} 和 {}", streamKey, reverseStreamKey);
                } else {
                    // 非HTTP协议，直接return
                    return;
                }
            } else {
                // 第一次见到的包没payload，等后续包
                return;
            }
        }

        long seq = tcpHeader.getSequenceNumber();

        // 处理拦截器
        SimplePacketInfo simplePacketInfo = new SimplePacketInfo(srcIp, srcPort, dstIp, dstPort, streamKey);
        if (!handleInterceptorsBefore(simplePacketInfo, packet)) {
            return;
        }

        // 调试日志
        log.debug("[包] 流: {}, SEQ={}, 负载长度={}, FIN={}",
                streamKey, seq, payload.length, tcpHeader.getFin());

        // 计算当前流对应的处理队列索引（核心优化点：按流分片到固定队列）
        int queueIndex = Math.abs(streamKey.hashCode() % processPoolSize);

        // 将数据包处理逻辑提交到对应队列（保证同一流的包顺序执行）
        streamQueues.get(queueIndex).offer(() -> processPacket(
                streamKey, reverseStreamKey, tcpHeader, seq, payload, simplePacketInfo, packet
        ));
    }

    // 数据包实际处理逻辑（原gotPacket的核心逻辑迁移至此）
    private void processPacket(
            String streamKey, String reverseStreamKey, TcpPacket.TcpHeader tcpHeader,
            long seq, byte[] payload, SimplePacketInfo simplePacketInfo, Packet packet
    ) {
        // 处理SYN包
        if (handleSynPacket(streamKey, tcpHeader, seq)) {
            return;
        }

        // 忽略无负载且非FIN的包
        if (payload.length == 0 && !tcpHeader.getFin()) return;

        // 判断是请求还是响应
        boolean isRequest = isHttpRequest(payload);
        boolean isResponse = isHttpResponse(payload);

        // 存储数据包到相应的流
        if (isRequest) {
            log.debug("[请求] 识别为HTTP请求: {}", streamKey);
            storeTcpPacket(streamKey, seq, payload, true);
            updateExpectedSequence(streamKey, seq, payload.length, true);
            requestLastActiveTime.put(streamKey, System.currentTimeMillis());

            // 检查HTTP请求是否已完成
            SortedMap<Long, byte[]> packets = httpRequestStreams.get(streamKey);
            if (packets != null && !packets.isEmpty()) {
                byte[] reassembled = reassembleTcpStream(packets);
                if (isHttpRequestComplete(reassembled)) {
                    handleCompleteRequest(streamKey, simplePacketInfo, packet);
                }
            }
        } else if (isResponse) {
            log.debug("[响应] 识别为HTTP响应: {}", reverseStreamKey);
            handleResponsePacket(reverseStreamKey, seq, payload, simplePacketInfo, packet);
        } else {
            // 无法确定是请求还是响应，尝试根据流状态判断
            if (httpRequestStreams.containsKey(streamKey)) {
                log.debug("[请求] 根据流状态识别为HTTP请求: {}", streamKey);
                storeTcpPacket(streamKey, seq, payload, true);
                updateExpectedSequence(streamKey, seq, payload.length, true);
                requestLastActiveTime.put(streamKey, System.currentTimeMillis());
            } else if (httpResponseStreams.containsKey(reverseStreamKey)) {
                log.debug("[响应] 根据流状态识别为HTTP响应: {}", reverseStreamKey);
                handleResponsePacket(reverseStreamKey, seq, payload, simplePacketInfo, packet);
            } else {
                log.debug("[未知] 无法识别包类型，但属于HTTP流: {}", streamKey);
            }
        }

        // 处理FIN包（流结束）
        if (tcpHeader.getFin()) {
            if (isRequest) {
                handleFinPacket(streamKey, simplePacketInfo, packet, true);
            } else if (isResponse) {
                handleFinPacket(reverseStreamKey, simplePacketInfo, packet, false);
            } else {
                // 尝试根据流状态判断FIN包类型
                if (httpRequestStreams.containsKey(streamKey)) {
                    handleFinPacket(streamKey, simplePacketInfo, packet, true);
                } else if (httpResponseStreams.containsKey(reverseStreamKey)) {
                    handleFinPacket(reverseStreamKey, simplePacketInfo, packet, false);
                }
            }
        }
    }

    private void handleResponsePacket(String reverseStreamKey, long seq, byte[] payload, SimplePacketInfo simplePacketInfo, Packet packet) {
        storeTcpPacket(reverseStreamKey, seq, payload, false);
        updateExpectedSequence(reverseStreamKey, seq, payload.length, false);
        responseLastActiveTime.put(reverseStreamKey, System.currentTimeMillis());

        // 获取当前流的包集合
        SortedMap<Long, byte[]> packets = httpResponseStreams.get(reverseStreamKey);
        if (packets == null || packets.isEmpty()) return;

        // 检查是否为分块编码且未完成
        if (responseExpectedLength.containsKey(reverseStreamKey) &&
                responseExpectedLength.get(reverseStreamKey) == -1) {

            // 检查最后几个包是否包含分块结束标记
            if (hasChunkedEndMarker(packets)) {
                log.debug("[分块] 检测到结束标记，尝试完成响应: {}", reverseStreamKey);
                byte[] reassembled = reassembleTcpStream(packets);
                if (isHttpResponseComplete(reassembled)) {
                    handleCompleteResponse(reverseStreamKey, simplePacketInfo, packet);
                }
                return;
            }
        }


        // 仅在未缓存头部信息时尝试解析
        if (!responseExpectedLength.containsKey(reverseStreamKey)) {
            byte[] reassembled = reassembleTcpStream(packets);
            if (isHttpResponseComplete(reassembled)) {
                handleCompleteResponse(reverseStreamKey, simplePacketInfo, packet);
            } else {
                // 尝试解析头部以获取Content-Length
                int headerEndIndex = HttpHeaderUtils.findHttpHeaderEnd(reassembled);
                if (headerEndIndex != -1) {
                    Map<String, String> headers = HttpHeaderUtils.parseRespHeaders(reassembled);
                    String contentLengthStr = headers.get("content-length");
                    if (contentLengthStr != null) {
                        try {
                            int contentLength = Integer.parseInt(contentLengthStr);
                            int totalLength = headerEndIndex + 4 + contentLength;
                            responseExpectedLength.put(reverseStreamKey, totalLength);
                            responseCurrentLength.put(reverseStreamKey, reassembled.length);
                        } catch (NumberFormatException e) {
                            log.warn("Invalid Content-Length: {}", contentLengthStr);
                        }
                    } else if (headers.containsKey("transfer-encoding")) {
                        // 分块编码，无法简单通过长度判断，仍需重组检查
                        responseExpectedLength.put(reverseStreamKey, -1);
                    }
                }
            }
        } else {
            // 已缓存头部信息，更新当前长度并检查
            Integer currentLenObj = responseCurrentLength.get(reverseStreamKey);
            if (currentLenObj != null) {
                int currentLen = currentLenObj + payload.length;
                responseCurrentLength.put(reverseStreamKey, currentLen);
                Integer expectedLenObj = responseExpectedLength.get(reverseStreamKey);

                if (expectedLenObj != null) {
                    int expectedLen = expectedLenObj;
                    if (expectedLen != -1 && currentLen >= expectedLen) {
                        byte[] reassembled = reassembleTcpStream(packets);
                        if (isHttpResponseComplete(reassembled)) {
                            handleCompleteResponse(reverseStreamKey, simplePacketInfo, packet);
                        }
                    }
                }
            } else {
                // 如果没有找到当前长度记录，可能需要重新初始化
                log.debug("[响应] 未找到流的当前长度记录，尝试重新初始化: {}", reverseStreamKey);
                // 重新尝试解析头部信息
                byte[] reassembled = reassembleTcpStream(packets);
                int headerEndIndex = HttpHeaderUtils.findHttpHeaderEnd(reassembled);
                if (headerEndIndex != -1) {
                    Map<String, String> headers = HttpHeaderUtils.parseRespHeaders(reassembled);
                    String contentLengthStr = headers.get("content-length");
                    if (contentLengthStr != null) {
                        try {
                            int contentLength = Integer.parseInt(contentLengthStr);
                            int totalLength = headerEndIndex + 4 + contentLength;
                            responseExpectedLength.put(reverseStreamKey, totalLength);
                            responseCurrentLength.put(reverseStreamKey, reassembled.length);
                        } catch (NumberFormatException e) {
                            log.warn("无效的Content-Length: {}", contentLengthStr);
                        }
                    } else if (headers.containsKey("transfer-encoding")) {
                        // 分块编码，无法简单通过长度判断，仍需重组检查
                        responseExpectedLength.put(reverseStreamKey, -1);
                        responseCurrentLength.put(reverseStreamKey, reassembled.length);
                    }
                }
            }
        }
    }

    /**
     * 判断是否为HTTP请求
     */
    private boolean isHttpRequest(byte[] payload) {
        if (payload.length == 0) return false;
        String payloadStr = new String(payload, StandardCharsets.US_ASCII);
        return payloadStr.startsWith("GET ") ||
                payloadStr.startsWith("POST ") ||
                payloadStr.startsWith("HEAD ") ||
                payloadStr.startsWith("PUT ") ||
                payloadStr.startsWith("DELETE ") ||
                payloadStr.startsWith("OPTIONS ") ||
                payloadStr.startsWith("PATCH ");
    }

    /**
     * 处理拦截器的beforeHandle逻辑
     */
    private boolean handleInterceptorsBefore(SimplePacketInfo info, Packet packet) {
        if (interceptors == null) return true;
        for (HttpPacketInterceptor interceptor : interceptors) {
            if (!interceptor.beforeHandle(info, packet)) {
                return false;
            }
        }
        return true;
    }

    /**
     * 处理SYN包初始化逻辑
     */
    private boolean handleSynPacket(String streamKey, TcpPacket.TcpHeader header, long seq) {
        if (header.getSyn() && !header.getAck()) {
            requestExpectedSeq.put(streamKey, seq + 1);
            responseExpectedSeq.put(streamKey, seq + 1);
            log.debug("[SYN] 新流初始化: {}", streamKey);
            return true;
        }
        return false;
    }

    /**
     * 存储TCP数据包到流
     */
    private void storeTcpPacket(String streamKey, long seq, byte[] payload, boolean isRequest) {
        Map<String, SortedMap<Long, byte[]>> targetMap = isRequest ? httpRequestStreams : httpResponseStreams;
        SortedMap<Long, byte[]> streamPackets = targetMap.computeIfAbsent(
                streamKey, k -> new ConcurrentSkipListMap<>(new SequenceComparator())
        );
        streamPackets.put(seq, payload);
    }


    /**
     * 更新预期的下一个序列号
     */
    private void updateExpectedSequence(String streamKey, long currentSeq, int payloadLength, boolean isRequest) {
        Map<String, Long> targetMap = isRequest ? requestExpectedSeq : responseExpectedSeq;
        Long expected = targetMap.get(streamKey);
        if (expected != null && currentSeq == expected) {
            targetMap.put(streamKey, currentSeq + payloadLength);
        }
    }

    /**
     * 清理超时无活动的流
     */
    private void cleanupExpiredStreams() {
        long timeoutMillis = 5 * 60 * 1000; // 5分钟超时
        long now = System.currentTimeMillis();

        // 清理请求流
        requestLastActiveTime.entrySet().removeIf(entry -> {
            String key = entry.getKey();
            long lastActive = entry.getValue();
            if (now - lastActive > timeoutMillis) {
                httpRequestStreams.remove(key);
                requestExpectedSeq.remove(key);
                log.debug("[清理] 超时请求流: {}", key);
                return true;
            }
            return false;
        });

        // 清理响应流
        responseLastActiveTime.entrySet().removeIf(entry -> {
            String key = entry.getKey();
            long lastActive = entry.getValue();
            if (now - lastActive > timeoutMillis) {
                httpResponseStreams.remove(key);
                responseExpectedSeq.remove(key);
                log.debug("[清理] 超时响应流: {}", key);
                return true;
            }
            return false;
        });
    }

    /**
     * 重组并生成完整的HTTP响应
     */
    private HttpResponseData saveCompleteResponse(String streamKey) {
        SortedMap<Long, byte[]> packets = httpResponseStreams.get(streamKey);
        if (packets == null || packets.isEmpty()) {
            log.info("[保存] 响应流无数据: {}", streamKey);
            return null;
        }

        // 1. 重组TCP流数据
        byte[] fullResponse = reassembleTcpStream(packets);
        log.info("[保存] 响应重组后总长度: {}字节", fullResponse.length);

        // 2. 分离HTTP头部和响应体
        int headerEndIndex = HttpHeaderUtils.findHttpHeaderEnd(fullResponse);
        byte[] headerBytes = new byte[0];
        byte[] bodyBytes = fullResponse;

        if (headerEndIndex != -1) {
            headerBytes = Arrays.copyOfRange(fullResponse, 0, headerEndIndex);
            bodyBytes = Arrays.copyOfRange(fullResponse, headerEndIndex + 4, fullResponse.length);
        } else {
            log.warn("[保存] 未找到完整HTTP头部，保存全部数据");
        }

        HttpResponseData responseData = new HttpResponseData(headerBytes);

        // 3. 处理响应体编码
        byte[] decodedBody = decodeResponseBody(bodyBytes, responseData.getHeaders());
        responseData.setBodyBytes(decodedBody);

        return responseData;
    }

    /**
     * 重组TCP流数据（处理序列号回绕和数据重叠）
     */
    private static byte[] reassembleTcpStream(SortedMap<Long, byte[]> packets) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            if (packets.isEmpty()) return new byte[0];
            long currentSeq = packets.firstKey();
            for (Map.Entry<Long, byte[]> entry : packets.entrySet()) {
                long seq = entry.getKey();
                byte[] data = entry.getValue();
                int dataLen = data.length;

                long seqDistance = sequenceDistance(currentSeq, seq);

                if (seqDistance < 0) {
                    // 处理回绕情况
                    if (seq < currentSeq && currentSeq - seq > 0x7FFFFFFFL) {
                        // 序列号回绕，实际是新区间
                        baos.write(data);
                        currentSeq = seq + dataLen;
                    } else {
                        log.debug("[重组] 跳过重复/过时包: SEQ={} (预期={})", seq, currentSeq);
                    }
                    continue;
                } else if (seqDistance > 0) {
                    log.warn("[重组] 数据间隙: 预期SEQ={}, 实际SEQ={}, 间隙={}字节", currentSeq, seq, seqDistance);
                    // 尝试继续处理后续数据
                    baos.write(data);
                    currentSeq = seq + dataLen;
                    continue;
                }

                // 处理连续或重叠数据
                int overlap = (int) (currentSeq - seq);
                if (overlap < dataLen) {
                    int validLength = dataLen - overlap;
                    baos.write(data, overlap, validLength);
                    currentSeq = seq + dataLen;
                } else {
                    log.debug("[重组] 数据完全重叠: SEQ={}, 长度={}, 当前位置={}", seq, dataLen, currentSeq);
                }
            }
            return baos.toByteArray();
        } catch (IOException e) {
            log.error("[重组] 流重组失败: {}", e.getMessage());
            return new byte[0];
        }
    }
    /**
     * 32位序列号安全距离计算
     */
    private static long sequenceDistance(long expected, long actual) {
        long uExpected = expected & 0xFFFFFFFFL;
        long uActual = actual & 0xFFFFFFFFL;

        if (uExpected > 0xF0000000L && uActual < 0x0FFFFFFFL) {
            return (uActual + 0x100000000L) - uExpected;
        } else if (uActual > 0xF0000000L && uExpected < 0x0FFFFFFFL) {
            return uActual - (uExpected + 0x100000000L);
        }

        return uActual - uExpected;
    }

    /**
     * 解码响应体（支持gzip、deflate、chunked）
     */
    private byte[] decodeResponseBody(byte[] rawBody, Map<String, String> headers) {
        byte[] decoded = rawBody;

        // 处理分块编码
        if (headers.getOrDefault("Transfer-Encoding", "").toLowerCase().contains("chunked")) {
            log.info("[解码] 处理分块编码...");
            decoded = decodeChunked(rawBody);
            if (decoded == null) {
                log.warn("[解码] 分块解码失败，使用原始数据");
                decoded = rawBody;
            }
        }

        // 处理gzip压缩
        if (headers.getOrDefault("Content-Encoding", "").toLowerCase().contains("gzip")) {
            log.info("[解码] 处理gzip压缩...");
            decoded = decompressGzip(decoded);
            if (decoded == null) {
                log.warn("[解码] gzip解压失败，使用当前数据");
            }
        }

        // 处理deflate压缩
        if (headers.getOrDefault("Content-Encoding", "").toLowerCase().contains("deflate")) {
            log.info("[解码] 处理deflate压缩...");
            decoded = decompressDeflate(decoded);
            if (decoded == null) {
                log.warn("[解码] deflate解压失败，使用当前数据");
            }
        }

        return decoded;
    }

    /**
     * 分块编码解码
     */
    private byte[] decodeChunked(byte[] chunkedData) {
        try (ByteArrayInputStream in = new ByteArrayInputStream(chunkedData);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {

            while (true) {
                String lengthLine = readLine(in);
                if (lengthLine == null) break;

                lengthLine = lengthLine.trim().split(";", 2)[0];
                if (lengthLine.isEmpty()) continue;

                int chunkLength;
                try {
                    chunkLength = Integer.parseInt(lengthLine, 16);
                } catch (NumberFormatException e) {
                    log.warn("[分块] 无效长度格式: {}，使用原始数据", lengthLine);
                    return chunkedData;
                }

                if (chunkLength == 0) {
                    // 读取结束块后的trailer
                    while (true) {
                        String trailerLine = readLine(in);
                        if (trailerLine == null || trailerLine.trim().isEmpty()) {
                            break;
                        }
                    }
                    break;
                }

                // 读取块数据（处理不完整情况）
                byte[] chunk = new byte[chunkLength];
                int totalRead = 0;
                int bytesRead;
                while (totalRead < chunkLength && (bytesRead = in.read(chunk, totalRead, chunkLength - totalRead)) != -1) {
                    totalRead += bytesRead;
                }
                if (totalRead != chunkLength) {
                    log.warn("[分块] 数据不完整，期望 {} 字节，实际读取 {}", chunkLength, totalRead);
                    return chunkedData;
                }
                out.write(chunk, 0, totalRead);

                // 跳过块结束符
                String endCRLF = readLine(in);
                if (endCRLF == null) {
                    log.warn("[分块] 意外结束，缺少CRLF");
                    break;
                }
            }

            return out.toByteArray();
        } catch (Exception e) {
            log.error("[分块] 解码异常: {}", e.getMessage());
            return chunkedData;
        }
    }

    /**
     * 读取一行（支持\r\n或\n）
     */
    private String readLine(ByteArrayInputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        boolean lastWasCR = false;
        while ((b = in.read()) != -1) {
            if (b == '\n') {
                return sb.toString();
            } else if (b == '\r') {
                lastWasCR = true;
            } else {
                if (lastWasCR) {
                    sb.append('\r');
                    lastWasCR = false;
                }
                sb.append((char) b);
            }
        }
        if (sb.length() > 0 || lastWasCR) {
            if (lastWasCR) sb.append('\r');
            return sb.toString();
        }
        return null;
    }

    /**
     * Gzip解压
     */
    private byte[] decompressGzip(byte[] data) {
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(data));
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[4096];
            int len;
            while ((len = gis.read(buffer)) > 0) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        } catch (Exception e) {
            log.error("[gzip] 解压异常: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Deflate解压
     */
    private byte[] decompressDeflate(byte[] data) {
        try (InflaterInputStream iis = new InflaterInputStream(new ByteArrayInputStream(data));
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[4096];
            int len;
            while ((len = iis.read(buffer)) > 0) {
                bos.write(buffer, 0, len);
            }
            return bos.toByteArray();
        } catch (Exception e) {
            log.error("[deflate] 解压异常: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 关闭资源（定时任务和线程池）
     */
    public void shutdown() {
        // 关闭处理线程池
        processPool.shutdown();
        try {
            if (!processPool.awaitTermination(1, TimeUnit.SECONDS)) {
                processPool.shutdownNow();
            }
        } catch (InterruptedException e) {
            processPool.shutdownNow();
        }

        // 关闭定时任务线程池
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(1, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
        }
    }


    public String buildStreamKey(String srcIp, int srcPort, String dstIp, int dstPort) {
        return srcIp + ":" + srcPort + "-" + dstIp + ":" + dstPort;
    }

    /**
     * 生成请求唯一标识（streamKey + 起始序列号）
     */
    private String buildRequestId(String streamKey, long startSeq) {
        return streamKey + "-" + startSeq;
    }

    /**
     * 序列号比较器（处理32位回绕）
     */
    static class SequenceComparator implements Comparator<Long> {
        @Override
        public int compare(Long seq1, Long seq2) {
            long uSeq1 = seq1 & 0xFFFFFFFFL;
            long uSeq2 = seq2 & 0xFFFFFFFFL;

            if (uSeq1 - uSeq2 > 0x7FFFFFFFL) {
                return -1;
            } else if (uSeq2 - uSeq1 > 0x7FFFFFFFL) {
                return 1;
            }

            return Long.compare(uSeq1, uSeq2);
        }
    }

    /**
     * 自定义线程工厂，用于标识处理线程
     */
    static class StreamThreadFactory implements ThreadFactory {
        private static final AtomicInteger poolNumber = new AtomicInteger(1);
        private final ThreadGroup group;
        private final AtomicInteger threadNumber = new AtomicInteger(1);
        private final String namePrefix;

        StreamThreadFactory() {
            // 移除对SecurityManager的依赖，直接使用当前线程的线程组
            group = Thread.currentThread().getThreadGroup();
            namePrefix = "stream-processor-pool-" + poolNumber.getAndIncrement() + "-thread-";
        }

        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r, namePrefix + threadNumber.getAndIncrement(), 0);
            if (t.isDaemon()) {
                t.setDaemon(false);
            }
            if (t.getPriority() != Thread.NORM_PRIORITY) {
                t.setPriority(Thread.NORM_PRIORITY);
            }
            return t;
        }
    }

    /**
     * 判断是否为HTTP响应
     */
    private boolean isHttpResponse(byte[] payload) {
        if (payload.length == 0) return false;
        String payloadStr = new String(payload, StandardCharsets.US_ASCII);
        return payloadStr.startsWith("HTTP/");
    }

    /**
     * 检查HTTP响应是否完整
     */
    private boolean isHttpResponseComplete(byte[] responseData) {
        if (responseData == null || responseData.length == 0) {
            return false;
        }

        // 1. 查找头部结束位置
        int headerEndIndex = HttpHeaderUtils.findHttpHeaderEnd(responseData);
        if (headerEndIndex == -1) {
            log.debug("[响应完成检查] 未找到完整HTTP头部");
            return false; // 没有完整头部
        }

        // 2. 解析头部
        Map<String, String> headers = HttpHeaderUtils.parseRespHeaders(responseData);
        log.debug("[响应完成检查] 解析到的头部: {}", headers);

        // 3. 检查是否有Content-Length头
        String contentLengthStr = headers.get("content-length");
        if (contentLengthStr != null) {
            try {
                int contentLength = Integer.parseInt(contentLengthStr);
                int bodyStartIndex = headerEndIndex + 4; // \r\n\r\n之后是body开始
                if (responseData.length >= bodyStartIndex + contentLength) {
                    log.info("[响应完成检查] 基于Content-Length判断响应完成: {}字节", contentLength);
                    return true; // 已收到完整body
                } else {
                    log.debug("[响应完成检查] 响应体不完整: 期望{}字节，实际{}字节",
                            contentLength, responseData.length - bodyStartIndex);
                }
            } catch (NumberFormatException e) {
                log.warn("无效的Content-Length: {}", contentLengthStr);
            }
        }

        // 4. 检查是否是分块编码
        String transferEncoding = headers.get("transfer-encoding");
        if (transferEncoding != null && transferEncoding.equalsIgnoreCase("chunked")) {
            // 检查分块编码是否结束（以0\r\n\r\n结尾）
            String responseStr = new String(responseData, StandardCharsets.US_ASCII);
            if (responseStr.contains("0\r\n\r\n") || responseStr.endsWith("0\n\n")) {
                log.info("[响应完成检查] 基于分块编码判断响应完成");
                return true;
            } else {
                log.debug("[响应完成检查] 分块编码响应未完成");
            }
        }

        // 5. 如果没有Content-Length也不是分块编码，则根据连接关闭判断，需要等待FIN
        log.debug("[响应完成检查] 响应未完成，需要等待FIN包");
        return false;
    }


    /**
     * 处理FIN包（流结束标记）
     */
    private void handleFinPacket(String streamKey, SimplePacketInfo info, Packet packet, boolean isRequest) {
        log.debug("[FIN] 收到流结束标记: {} (是否请求: {})", streamKey, isRequest);

        if (isRequest) {
            // 处理未完成的请求
            SortedMap<Long, byte[]> packets = httpRequestStreams.get(streamKey);
            if (packets != null && !packets.isEmpty()) {
                long startSeq = packets.firstKey();
                String requestId = buildRequestId(streamKey, startSeq);
                if (!Boolean.TRUE.equals(singleRequestProcessed.get(requestId))) {
                    // 未处理过的请求才执行强制处理
                    byte[] reassembled = reassembleTcpStream(packets);
                    if (isHttpRequestComplete(reassembled)) {
                        handleCompleteRequest(streamKey, info, packet);
                    } else {
                        log.warn("[FIN] 请求{}未完成，强制处理", requestId);
                        HttpRequestData data = saveCompleteRequest(streamKey);
                        if (interceptors != null) {
                            for (HttpPacketInterceptor interceptor : interceptors) {
                                interceptor.onRequestComplete(data, info, packet);
                            }
                        }
                        singleRequestProcessed.put(requestId, true);
                    }
                }
            }

            // 清理请求流资源（TCP连接关闭，彻底清理）
            httpRequestStreams.remove(streamKey);
            requestExpectedSeq.remove(streamKey);
            requestLastActiveTime.remove(streamKey);
            log.debug("[FIN] 清理请求流资源: {}", streamKey);
        } else {
            // 处理未完成的响应
            SortedMap<Long, byte[]> packets = httpResponseStreams.get(streamKey);
            if (packets != null && !packets.isEmpty()) {
                long startSeq = packets.firstKey();
                String responseId = buildRequestId(streamKey, startSeq);
                if (!Boolean.TRUE.equals(singleResponseProcessed.get(responseId))) {
                    // 未处理过的响应才执行强制处理
                    byte[] reassembled = reassembleTcpStream(packets);
                    if (isHttpResponseComplete(reassembled)) {
                        handleCompleteResponse(streamKey, info, packet);
                    } else {
                        log.warn("[FIN] 响应{}未完成，强制处理", responseId);
                        HttpResponseData data = saveCompleteResponse(streamKey);
                        if (interceptors != null) {
                            for (HttpPacketInterceptor interceptor : interceptors) {
                                interceptor.onResponseComplete(data, info, packet);
                            }
                        }
                        singleResponseProcessed.put(responseId, true);
                    }
                }
            }

            // 清理响应流资源（TCP连接关闭，彻底清理）
            httpResponseStreams.remove(streamKey);
            responseExpectedSeq.remove(streamKey);
            responseLastActiveTime.remove(streamKey);
            responseExpectedLength.remove(streamKey);
            responseCurrentLength.remove(streamKey);
            log.debug("[FIN] 清理响应流资源: {}", streamKey);
        }
    }

    /**
     * 重组并生成完整的HTTP请求
     */
    private HttpRequestData saveCompleteRequest(String streamKey) {
        SortedMap<Long, byte[]> packets = httpRequestStreams.get(streamKey);
        if (packets == null || packets.isEmpty()) {
            log.info("[保存] 请求流无数据: {}", streamKey);
            return null;
        }

        // 1. 重组TCP流数据
        byte[] fullRequest = reassembleTcpStream(packets);
        log.info("[保存] 请求重组后总长度: {}字节", fullRequest.length);

        // 2. 分离HTTP头部和请求体
        int headerEndIndex = HttpHeaderUtils.findHttpHeaderEnd(fullRequest);
        byte[] headerBytes = new byte[0];
        byte[] bodyBytes = fullRequest;

        if (headerEndIndex != -1) {
            headerBytes = Arrays.copyOfRange(fullRequest, 0, headerEndIndex);
            bodyBytes = Arrays.copyOfRange(fullRequest, headerEndIndex + 4, fullRequest.length);
        } else {
            log.warn("[保存] 未找到完整HTTP头部，保存全部数据");
        }

        HttpRequestData requestData = new HttpRequestData(headerBytes);

        // 3. 处理请求体
        requestData.setBodyBytes(bodyBytes);

        return requestData;
    }

    /**
     * 检查HTTP请求是否完整
     */
    private boolean isHttpRequestComplete(byte[] requestData) {
        if (requestData == null || requestData.length == 0) {
            return false;
        }

        // 1. 查找头部结束位置
        int headerEndIndex = HttpHeaderUtils.findHttpHeaderEnd(requestData);
        if (headerEndIndex == -1) {
            return false; // 没有完整头部
        }

        // 2. 解析头部
        Map<String, String> headers = HttpHeaderUtils.parseReqHeaders(requestData);

        // 3. 检查是否有Content-Length头
        String contentLengthStr = headers.get("content-length");
        if (contentLengthStr != null) {
            try {
                int contentLength = Integer.parseInt(contentLengthStr);
                int bodyStartIndex = headerEndIndex + 4; // \r\n\r\n之后是body开始
                if (requestData.length >= bodyStartIndex + contentLength) {
                    return true; // 已收到完整body
                }
            } catch (NumberFormatException e) {
                log.warn("无效的Content-Length: {}", contentLengthStr);
            }
        } else {
            // 对于没有Content-Length的请求（如GET），头部结束即为完整
            return true;
        }

        return false;
    }

    /**
     * 处理完整的HTTP请求
     */
    private void handleCompleteRequest(String streamKey, SimplePacketInfo info, Packet packet) {
        // 获取当前请求的起始序列号（从存储的数据包中取第一个SEQ）
        SortedMap<Long, byte[]> requestPackets = httpRequestStreams.get(streamKey);
        if (requestPackets == null || requestPackets.isEmpty()) {
            return;
        }
        long startSeq = requestPackets.firstKey();
        String requestId = buildRequestId(streamKey, startSeq);

        // 检查当前请求是否已处理（避免重复）
        if (Boolean.TRUE.equals(singleRequestProcessed.get(requestId))) {
            log.debug("[HTTP] 请求已处理，跳过重复处理: {}", requestId);
            return;
        }

        // 处理请求并调用拦截器
        HttpRequestData httpRequestData = saveCompleteRequest(streamKey);
        if (interceptors != null) {
            for (HttpPacketInterceptor interceptor : interceptors) {
                interceptor.onRequestComplete(httpRequestData, info, packet);
            }
        }

        // 标记当前请求为已处理
        singleRequestProcessed.put(requestId, true);
        // 清理当前请求的数据包（保留TCP流，允许后续请求）
        requestPackets.clear();
        // 移除已处理的请求ID（避免内存泄漏）
        singleRequestProcessed.remove(requestId);
        log.debug("[HTTP] 请求已完成并处理: {}", requestId);
    }

    /**
     * 处理完整的HTTP响应
     */
    private void handleCompleteResponse(String streamKey, SimplePacketInfo info, Packet packet) {
        SortedMap<Long, byte[]> responsePackets = httpResponseStreams.get(streamKey);
        if (responsePackets == null || responsePackets.isEmpty()) return;

        long startSeq = responsePackets.firstKey();
        String responseId = buildRequestId(streamKey, startSeq);

        if (Boolean.TRUE.equals(singleResponseProcessed.get(responseId))) {
            log.debug("[HTTP] 响应已处理，跳过重复处理: {}", responseId);
            return;
        }

        HttpResponseData httpResponseData = saveCompleteResponse(streamKey);
        if (interceptors != null) {
            for (HttpPacketInterceptor interceptor : interceptors) {
                interceptor.onResponseComplete(httpResponseData, info, packet);
            }
        }

        singleResponseProcessed.put(responseId, true);

        // 彻底清理响应流状态
        responsePackets.clear();
        responseExpectedSeq.remove(streamKey);
        responseLastActiveTime.remove(streamKey);
        responseExpectedLength.remove(streamKey);
        responseCurrentLength.remove(streamKey);
        singleResponseProcessed.remove(responseId);

        log.debug("[HTTP] 响应已完成并处理: {}", responseId);
    }

    /**
     * 检查最后几个包是否包含分块结束标记
     */
    private boolean hasChunkedEndMarker(SortedMap<Long, byte[]> packets) {
        if (packets.isEmpty()) return false;

        // 获取最后几个包的数据
        List<byte[]> lastPackets = new ArrayList<>();
        int count = 0;
        int maxPackets = 3; // 检查最后3个包

        // 从后往前取包
        Long lastKey = packets.lastKey();
        while (lastKey != null && count < maxPackets) {
            byte[] data = packets.get(lastKey);
            if (data != null) {
                lastPackets.add(data);
            }

            // 获取前一个键
            SortedMap<Long, byte[]> headMap = packets.headMap(lastKey);
            if (headMap.isEmpty()) break;
            lastKey = headMap.lastKey();
            count++;
        }

        // 检查分块结束标记
        for (byte[] data : lastPackets) {
            String str = new String(data, StandardCharsets.US_ASCII);
            if (str.contains("0\r\n\r\n") || str.endsWith("0\n\n")) {
                return true;
            }
        }

        // 检查跨包情况
        if (lastPackets.size() >= 2) {
            for (int i = 0; i < lastPackets.size() - 1; i++) {
                byte[] first = lastPackets.get(i);
                byte[] second = lastPackets.get(i + 1);

                // 检查第一个包的结尾和第二个包的开头
                int checkLen = Math.min(5, first.length);
                String endOfFirst = new String(Arrays.copyOfRange(first, first.length - checkLen, first.length),
                        StandardCharsets.US_ASCII);
                String startOfSecond = new String(Arrays.copyOfRange(second, 0, Math.min(5, second.length)),
                        StandardCharsets.US_ASCII);

                if ((endOfFirst + startOfSecond).contains("0\r\n\r\n")) {
                    return true;
                }
            }
        }

        return false;
    }
}
