package org.example.pcaptest.core.entity;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SimplePacketInfo {

    private String srcIp;

    private Integer srcPort;

    private String dstIp;

    private Integer dstPort;

    /**
     * 一个请求的唯一标识
     */
    private String streamKey;


}
