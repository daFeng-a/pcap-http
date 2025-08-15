package org.example.pcaptest.core;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;

import java.util.List;

@Slf4j
public class HttpPcapProcessor {

    private final HttpPacketListener httpPacketListener;

    public HttpPcapProcessor(HttpPacketListener httpPacketListener) {
        this.httpPacketListener = httpPacketListener;
    }

    public void start(Integer selectedInterfaceIndex) throws Exception {
        // 获取网络接口列表
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        if (allDevs.isEmpty()) {
            log.error("未找到网络接口！");
            return;
        }

        // 打印接口列表供选择
        log.info("可用网络接口：");
        for (int i = 0; i < allDevs.size(); i++) {
            log.info("[{}] {}", i, allDevs.get(i).getDescription());
        }

        if (selectedInterfaceIndex == null){
            log.error("请选择网络接口索引！当前值为NULL！");
            throw new Exception("请选择网络接口索引！");
        }

        // 选择接口
        if (selectedInterfaceIndex >= allDevs.size()) {
            log.error("错误：无效的接口索引！");
            return;
        }
        PcapNetworkInterface device = allDevs.get(selectedInterfaceIndex);
        log.info("选择接口: {}", device.getDescription());

        // 增加抓包长度到最大合法值
        int snapLen = 65535;

        PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 100; // 超时时间（毫秒）
        PcapHandle handle = new PcapHandle.Builder(device.getName())
                .snaplen(snapLen)
                .promiscuousMode(mode)
                .timeoutMillis(timeout)
                .bufferSize(4 * 1024 * 1024)  // 设置缓冲区大小为4MB
                .build();

        // 设置过滤器：只捕获目标端口的TCP流量
        String filter = "tcp";
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        log.info("过滤器: {}", filter);

        try {
            log.info("开始捕获响应...");
            handle.loop(-1, httpPacketListener); // 无限循环捕获
        } catch (InterruptedException e) {
            log.warn("捕获被中断: {}", e.getMessage());
        } finally {
            handle.close();
            log.info("已关闭网络接口");
        }
    }
}
