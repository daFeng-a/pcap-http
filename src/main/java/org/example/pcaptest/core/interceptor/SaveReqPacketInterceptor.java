package org.example.pcaptest.core.interceptor;

import lombok.extern.slf4j.Slf4j;
import org.example.pcaptest.core.entity.HttpRequestData;
import org.example.pcaptest.core.entity.HttpResponseData;
import org.example.pcaptest.core.entity.SimplePacketInfo;
import org.pcap4j.packet.Packet;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;

@Slf4j
@Component
public class SaveReqPacketInterceptor implements HttpPacketInterceptor {

    // 时间格式化（用于生成唯一文件名）
    private static final SimpleDateFormat FILE_DATE_FORMAT = new SimpleDateFormat("yyyyMMdd_HHmmss_SSS");

    // 响应保存目录（自动创建）
    private static final String SAVE_DIR = "http_responses/";

    public SaveReqPacketInterceptor(){
        new File(SAVE_DIR).mkdirs();
        log.info("已创建响应保存目录: {}", SAVE_DIR);
    }

    @Override
    public void onRequestComplete(HttpRequestData requestData, SimplePacketInfo info, Packet packet) {
        // 4. 生成唯一文件名（流标识+时间戳）
        String timestamp = FILE_DATE_FORMAT.format(new Date());
        String fileName = SAVE_DIR + "request_" + info.getStreamKey().replace(":", "_") + "_" + timestamp;

        // 5. 保存头部（可选，方便调试）
        saveToFile(requestData.getHeaderBytes(), fileName + ".txt");
    }

    @Override
    public void onResponseComplete(HttpResponseData httpResponseData, SimplePacketInfo simplePacketInfo, Packet packet) {
        // 4. 生成唯一文件名（流标识+时间戳）
        String timestamp = FILE_DATE_FORMAT.format(new Date());
        String fileName = SAVE_DIR + "response_" + simplePacketInfo.getStreamKey().replace(":", "_") + "_" + timestamp;

        // 5. 保存头部（可选，方便调试）
        saveToFile(httpResponseData.getHeaderBytes(), fileName + "_header.txt");

        // 6. 保存响应体（核心内容）
        saveToFile(httpResponseData.getBodyBytes(), fileName + "_body.bin");

        try {
            String bodyStr = new String(httpResponseData.getBodyBytes(), StandardCharsets.UTF_8);
            saveToFile(bodyStr.getBytes(StandardCharsets.UTF_8), fileName + "_body.txt");
        } catch (Exception e) {
            // 非文本类型无需处理
            log.info("[保存] 响应体为二进制数据，不保存文本形式");
        }

    }

    /**
     * 保存字节数组到文件
     */
    private void saveToFile(byte[] data, String filePath) {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(data);
            log.info("[保存] 文件已写入: {} ({}字节)", filePath, data.length);
        } catch (IOException e) {
            log.error("[保存] 写入失败 {}: {}", filePath, e.getMessage());
        }
    }
}
