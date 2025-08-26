package org.example.pcaptest.core;

import lombok.extern.slf4j.Slf4j;
import org.example.pcaptest.core.entity.HttpResponseData;
import org.example.pcaptest.core.entity.SimplePacketInfo;
import org.example.pcaptest.core.interceptor.PacketInterceptor;
import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

@Slf4j
public class HttpPacketListener implements PacketListener {

    // 存储HTTP响应流（线程安全，使用自定义StreamKey和ConcurrentSkipListMap）
    private final Map<String, SortedMap<Long, byte[]>> httpResponseStreams = new ConcurrentHashMap<>();
    // 存储每个流的预期下一个序列号（线程安全）
    private final Map<String, Long> streamExpectedSeq = new ConcurrentHashMap<>();
    // 记录流最后活动时间（用于超时清理）
    private final Map<String, Long> streamLastActiveTime = new ConcurrentHashMap<>();
    // 存储HTTP流的StreamKey
    private final Set<String> httpStreams = ConcurrentHashMap.newKeySet();

    // 定时清理超时流的调度器
    private final ScheduledExecutorService scheduler;

    private final List<PacketInterceptor> interceptors;

    public HttpPacketListener(List<PacketInterceptor> interceptors) {
        this.interceptors = interceptors;
        this.scheduler = Executors.newSingleThreadScheduledExecutor();
        // 每10秒清理一次30秒无活动的流
        this.scheduler.scheduleAtFixedRate(this::cleanupExpiredStreams, 0, 10, TimeUnit.SECONDS);
    }

    @Override
    public void gotPacket(Packet packet) {
        // 解析IP和TCP层（提取为独立方法，提升可读性）
        IpV4Packet ipV4 = packet.get(IpV4Packet.class);
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (ipV4 == null || tcp == null) return;

        // 提取基础信息
        TcpPacket.TcpHeader tcpHeader = tcp.getHeader();



        String srcIp = ipV4.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipV4.getHeader().getDstAddr().getHostAddress();
        int srcPort = tcpHeader.getSrcPort().valueAsInt();
        int dstPort = tcpHeader.getDstPort().valueAsInt();


        // 生成流标识（使用自定义对象替代字符串拼接）
        String streamKey = buildStreamKey(srcIp, srcPort, dstIp, dstPort);

        byte[] payload = tcp.getPayload() != null ? tcp.getPayload().getRawData() : new byte[0];
        // 只在新流第一个有payload的包做HTTP判断
        if (!httpStreams.contains(streamKey)) {
            if (payload.length > 0) {
                String payloadStr = new String(payload, StandardCharsets.US_ASCII);
                if (payloadStr.startsWith("GET ") ||
                        payloadStr.startsWith("POST ") ||
                        payloadStr.startsWith("HEAD ") ||
                        payloadStr.startsWith("PUT ") ||
                        payloadStr.startsWith("DELETE ") ||
                        payloadStr.startsWith("OPTIONS ") ||
                        payloadStr.startsWith("PATCH ") ||
                        payloadStr.startsWith("HTTP/")) {
                    httpStreams.add(streamKey); // 标记该流为HTTP
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
        SimplePacketInfo simplePacketInfo = new SimplePacketInfo(srcIp, srcPort, dstIp, dstPort,streamKey.toString());
        if (!handleInterceptorsBefore(simplePacketInfo, packet)) {
            return;
        }



        // 调试日志（降低级别，减少IO损耗）
        log.debug("[包] 响应流: {}, SEQ={}, 负载长度={}, FIN={}",
                streamKey, seq, payload.length, tcpHeader.getFin());

        // 处理SYN包（独立逻辑）
        if (handleSynPacket(streamKey, tcpHeader, seq)) {
            return;
        }

        // 忽略无负载且非FIN的包
        if (payload.length == 0 && !tcpHeader.getFin()) return;

        // 存储数据包到流（使用线程安全的有序集合）
        storeTcpPacket(streamKey, seq, payload);

        // 更新预期序列号
        updateExpectedSequence(streamKey, seq, payload.length);

        // 更新最后活动时间
        streamLastActiveTime.put(streamKey, System.currentTimeMillis());

        // 处理FIN包（流结束）
        if (tcpHeader.getFin()) {
            handleFinPacket(streamKey, simplePacketInfo, packet);
        }
    }

    /**
     * 处理拦截器的beforeHandle逻辑
     */
    private boolean handleInterceptorsBefore(SimplePacketInfo info, Packet packet) {
        if (interceptors == null) return true;
        for (PacketInterceptor interceptor : interceptors) {
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
            streamExpectedSeq.put(streamKey, seq + 1);
            log.debug("[SYN] 新响应流初始化: {}", streamKey);
            return true;
        }
        return false;
    }

    /**
     * 存储TCP数据包到流（使用支持序列号回绕的有序集合）
     */
    private void storeTcpPacket(String streamKey, long seq, byte[] payload) {
        SortedMap<Long, byte[]> streamPackets = httpResponseStreams.computeIfAbsent(
                streamKey, k -> new ConcurrentSkipListMap<>(new SequenceComparator())
        );
        streamPackets.put(seq, payload);
    }

    /**
     * 处理FIN包（重组并清理流）
     */
    private void handleFinPacket(String streamKey, SimplePacketInfo info, Packet packet) {
        HttpResponseData httpResponseData = saveCompleteResponse(streamKey);
        if (interceptors != null) {
            for (PacketInterceptor interceptor : interceptors) {
                interceptor.afterHandle(httpResponseData, info, packet);
            }
        }
        // 清理流数据
        httpResponseStreams.remove(streamKey);
        streamExpectedSeq.remove(streamKey);
        streamLastActiveTime.remove(streamKey);
        httpStreams.remove(streamKey);
        log.debug("[FIN] 流处理完成并清理: {}", streamKey);
    }

    /**
     * 更新预期的下一个序列号
     */
    private void updateExpectedSequence(String streamKey, long currentSeq, int payloadLength) {
        Long expected = streamExpectedSeq.get(streamKey);
        if (expected != null && currentSeq == expected) {
            streamExpectedSeq.put(streamKey, currentSeq + payloadLength);
        }
    }

    /**
     * 清理超时无活动的流（防止内存泄漏）
     */
    private void cleanupExpiredStreams() {
        long timeoutMillis = 5 * 60 * 1000; // 5分钟超时
        long now = System.currentTimeMillis();
        streamLastActiveTime.entrySet().removeIf(entry -> {
            String key = entry.getKey();
            long lastActive = entry.getValue();
            if (now - lastActive > timeoutMillis) {
                httpResponseStreams.remove(key);
                streamExpectedSeq.remove(key);
                log.debug("[清理] 超时流: {}", key);
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

        // 1. 重组TCP流数据（处理重叠）
        byte[] fullResponse = reassembleTcpStream(packets);
        log.info("[保存] 重组后总长度: {}字节", fullResponse.length);

        // 2. 分离HTTP头部和响应体
        int headerEndIndex = findHttpHeaderEnd(fullResponse);
        byte[] headerBytes = new byte[0];
        byte[] bodyBytes = fullResponse;

        if (headerEndIndex != -1) {
            headerBytes = Arrays.copyOfRange(fullResponse, 0, headerEndIndex);
            bodyBytes = Arrays.copyOfRange(fullResponse, headerEndIndex + 4, fullResponse.length);
        } else {
            log.warn("[保存] 未找到完整HTTP头部，保存全部数据");
        }

        HttpResponseData responseData = new HttpResponseData(headerBytes);

        // 3. 处理响应体编码（支持更多类型）
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

            // 已通过ConcurrentSkipListMap按SequenceComparator排序，直接遍历
            Long firstSeq = packets.firstKey();
            long currentSeq = firstSeq;
            long lastDataEnd = firstSeq;

            for (Map.Entry<Long, byte[]> entry : packets.entrySet()) {
                long seq = entry.getKey();
                byte[] data = entry.getValue();
                int dataLen = data.length;

                long seqDistance = sequenceDistance(currentSeq, seq);

                if (seqDistance < 0) {
                    // 情况1：重复包或已处理包（跳过）
                    log.debug("[重组] 跳过重复/过时包: SEQ={} (预期={})", seq, currentSeq);
                    continue;
                } else if (seqDistance > 0) {
                    // 情况2：数据间隙（记录警告）
                    log.warn("[重组] 数据间隙: 预期SEQ={}, 实际SEQ={}, 间隙={}字节",
                            currentSeq, seq, seqDistance);
                    if (seq > lastDataEnd) {
                        lastDataEnd = seq + dataLen;
                    }
                    continue;
                }

                // 情况3：连续数据（处理重叠）
                long nextSeq = seq + dataLen;
                if (nextSeq > currentSeq) {
                    int overlap = (int) (currentSeq - seq); // 计算重叠长度
                    int validLength = dataLen - overlap;
                    if (validLength > 0) {
                        baos.write(data, overlap, validLength); // 只写入非重叠部分
                    }
                    currentSeq = nextSeq;
                    lastDataEnd = currentSeq;
                } else {
                    log.debug("[重组] 数据完全重叠: SEQ={}, 长度={}, 当前位置={}", seq, dataLen, currentSeq);
                }
            }

            log.debug("[重组] 最大连续数据结束位置: {}", lastDataEnd);
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
     * 查找HTTP头部结束位置（严格匹配\r\n\r\n）
     */
    private static int findHttpHeaderEnd(byte[] data) {
        for (int i = 0; i < data.length - 3; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' &&
                    data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i;
            }
        }
        // 容错：尝试寻找\n\n作为结束标志（非标准）
        for (int i = 0; i < data.length - 1; i++) {
            if (data[i] == '\n' && data[i + 1] == '\n') {
                log.info("[头部] 发现非标准结束标志\\n\\n");
                return i;
            }
        }
        return -1;
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
     * 关闭资源（定时任务）
     */
    public void shutdown() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(1, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
        }
    }


    public String buildStreamKey(String srcIp, int srcPort, String dstIp, int dstPort){
        return srcIp + ":" + srcPort + "-" + dstIp + ":" + dstPort;
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
}