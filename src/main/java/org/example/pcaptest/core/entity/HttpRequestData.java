package org.example.pcaptest.core.entity;

import lombok.Data;
import org.example.pcaptest.core.util.HttpHeaderUtils;

import java.util.Map;

/**
 * HTTP请求数据实体
 */
@Data
public class HttpRequestData {
    private byte[] headerBytes;
    private byte[] bodyBytes;
    private Map<String, String> headers;

    public HttpRequestData(byte[] headerBytes) {
        this.headerBytes = headerBytes;
        this.headers = HttpHeaderUtils.parseReqHeaders(headerBytes);
    }
}