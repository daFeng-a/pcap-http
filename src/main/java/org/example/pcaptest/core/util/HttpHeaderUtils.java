package org.example.pcaptest.core.util;

import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class HttpHeaderUtils {

    /**
     * 解析HTTP请求头字节数组，提取键值对
     * @param headerBytes HTTP请求头的字节数组
     * @return 包含请求头键值对的Map
     */
    public static Map<String, String> parseReqHeaders(byte[] headerBytes) {
        Map<String, String> headers = new HashMap<>();

        if (headerBytes == null || headerBytes.length == 0) {
            return headers;
        }

        // 将字节数组转换为字符串，使用UTF-8编码
        String headerStr = new String(headerBytes, StandardCharsets.UTF_8);

        // 按行分割，Windows和Linux的换行符都要考虑
        String[] lines = headerStr.split("\r?\n");

        // 跳过第一行（请求行，如：GET /index.html HTTP/1.1）
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();

            // 空行表示头部结束
            if (line.isEmpty()) {
                break;
            }

            // 分割键和值（只分割第一个冒号）
            int colonIndex = line.indexOf(':');
            if (colonIndex != -1) {
                String key = line.substring(0, colonIndex).trim();
                String value = line.substring(colonIndex + 1).trim();
                headers.put(key, value);
            }
        }

        return headers;
    }


    /**
     * 从HTTP响应原始数据中解析头部键值对（仅解析首行和 headers）
     * @param fullResponse 重组后的HTTP响应原始字节
     * @return 头部键值对（键：小写，值：原始值）
     */
    public static Map<String, String> parseRespHeaders(byte[] fullResponse) {
        Map<String, String> headers = new HashMap<>();
        if (fullResponse == null || fullResponse.length == 0) {
            return headers;
        }

        // 1. 找到头部结束位置（复用已有逻辑）
        int headerEndIndex = findHttpHeaderEnd(fullResponse);
        if (headerEndIndex == -1) {
            log.debug("[解析头部] 未找到完整头部，无法解析");
            return headers;
        }

        // 2. 提取头部字节并转换为字符串（使用US-ASCII编码，HTTP头部标准编码）
        byte[] headerBytes = Arrays.copyOfRange(fullResponse, 0, headerEndIndex);
        String headerStr;
        try {
            headerStr = new String(headerBytes, StandardCharsets.US_ASCII);
        } catch (Exception e) {
            log.error("[解析头部] 编码转换失败", e);
            return headers;
        }

        // 3. 按行分割头部（兼容\r\n和\n换行）
        String[] lines = headerStr.split("\r?\n");
        if (lines.length == 0) {
            return headers;
        }

        // 4. 跳过响应首行（如HTTP/1.1 200 OK），解析后续头部行
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) {
                continue; // 跳过空行
            }

            // 分割键值对（按第一个冒号分割）
            int colonIndex = line.indexOf(':');
            if (colonIndex == -1) {
                log.debug("[解析头部] 无效头部格式（无冒号）: {}", line);
                continue;
            }

            String key = line.substring(0, colonIndex).trim().toLowerCase(); // 头部键统一转为小写
            String value = colonIndex + 1 < line.length()
                    ? line.substring(colonIndex + 1).trim()
                    : "";

            headers.put(key, value);
        }

        return headers;
    }

    /**
     * 查找HTTP头部结束位置（严格匹配\r\n\r\n）
     * 响应头，请求头均可
     */
    public static int findHttpHeaderEnd(byte[] data) {
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

}
