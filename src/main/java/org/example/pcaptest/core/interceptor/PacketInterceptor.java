package org.example.pcaptest.core.interceptor;

import org.example.pcaptest.core.entity.HttpResponseData;
import org.example.pcaptest.core.entity.SimplePacketInfo;
import org.pcap4j.packet.Packet;

/**
 * 数据包包拦截器，返回false就不执行后续解析的代码了
 */
public interface PacketInterceptor {

    /**
     * 验证数据包是否需处理
     * @param simplePacketInfo 简单数据包信息
     * @param packet 数据包
     * @return true 需要处理，false不需要
     */
    default boolean beforeHandle(SimplePacketInfo simplePacketInfo, Packet packet){
        return true;
    }

    /**
     * 后置处理
     * @param httpResponseData
     * @param simplePacketInfo
     * @param packet
     */
    void afterHandle(HttpResponseData httpResponseData, SimplePacketInfo simplePacketInfo, Packet packet);


}
