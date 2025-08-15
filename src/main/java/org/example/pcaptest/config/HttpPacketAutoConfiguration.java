package org.example.pcaptest.config;

import org.example.pcaptest.core.HttpPacketCommandLineRunner;
import org.example.pcaptest.core.HttpPacketListener;
import org.example.pcaptest.core.HttpPcapProcessor;
import org.example.pcaptest.core.interceptor.PacketInterceptor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import java.util.List;

/**
 * http抓包自动配置类
 */
@AutoConfiguration
@EnableConfigurationProperties(HttpPcapConfig.class)
@ConditionalOnProperty(prefix = "http.pacp", value = "enable", matchIfMissing = true)
public class HttpPacketAutoConfiguration {

    @Bean
    public HttpPacketListener getHttpPacketListener(List<PacketInterceptor> interceptors) {
        return new HttpPacketListener(interceptors);
    }

    @Bean
    public HttpPcapProcessor getHttpPcapProcessor(HttpPacketListener httpPacketListener) {
        return new HttpPcapProcessor(httpPacketListener);
    }

    @Bean
    public HttpPacketCommandLineRunner getHttpPacketCommandLineRunner(HttpPcapProcessor httpPcapProcessor,HttpPcapConfig httpPcapConfig) {
        return new HttpPacketCommandLineRunner(httpPcapProcessor,httpPcapConfig);
    }
}
