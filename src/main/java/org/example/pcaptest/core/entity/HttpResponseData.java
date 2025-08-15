package org.example.pcaptest.core.entity;

import lombok.Data;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Data
public class HttpResponseData {

    private Map<String, String> headers;

    // 响应头字节数组
    private byte[] headerBytes;
    // 响应体字节数组
    private byte[] bodyBytes;


    public HttpResponseData(byte[] headerBytes){
        this.headerBytes = headerBytes;
        this.headers = parseHeaders(headerBytes);
    }

    public HttpResponseData(byte[] headerBytes, byte[] bodyBytes) {
        this.headerBytes = headerBytes;
        this.bodyBytes = bodyBytes;
        // 初始化时解析响应头
        this.headers = parseHeaders(headerBytes);
    }

    /**
     * 解析响应头字节数组为键值对Map
     */
    private Map<String, String> parseHeaders(byte[] headerBytes) {
        Map<String, String> headers = new HashMap<>();
        if (headerBytes == null || headerBytes.length == 0) {
            return headers;
        }

        String headerStr = new String(headerBytes, StandardCharsets.US_ASCII);
        String[] lines = headerStr.split("\r\n");

        // 跳过第一行状态行（如HTTP/1.1 200 OK），从第二行开始解析头字段
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty()) {
                continue;
            }

            int colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                String key = line.substring(0, colonIndex).trim();
                String value = line.substring(colonIndex + 1).trim();
                headers.put(key, value);
            }
        }
        return headers;
    }


    /**
     * 根据键获取响应头值（忽略大小写）
     */
    public String getHeader(String key) {
        if (key == null || headers.isEmpty()) {
            return null;
        }
        // 支持忽略键的大小写（HTTP头字段名不区分大小写）
        String lowerKey = key.toLowerCase();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().toLowerCase().equals(lowerKey)) {
                return entry.getValue();
            }
        }
        return null;
    }
}
