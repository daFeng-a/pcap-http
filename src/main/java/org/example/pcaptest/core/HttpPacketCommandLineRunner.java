package org.example.pcaptest.core;

import org.example.pcaptest.config.HttpPcapConfig;
import org.springframework.boot.CommandLineRunner;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HttpPacketCommandLineRunner implements CommandLineRunner {

    private final HttpPcapProcessor httpPcapProcessor;

    public final HttpPcapConfig httpPcapConfig;


    public HttpPacketCommandLineRunner(HttpPcapProcessor httpPcapProcessor,HttpPcapConfig httpPcapConfig){
        this.httpPcapProcessor = httpPcapProcessor;
        this.httpPcapConfig = httpPcapConfig;
    }

    @Override
    public void run(String... args) throws Exception {
        httpPcapProcessor.start(httpPcapConfig.getInterfaceIndex());
    }
}
