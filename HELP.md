# 一个HTTP抓包程序

# 使用说明：

## Windows：

### 1.下载本地库支持

[Npcap: Windows Packet Capture Library & Driver](https://npcap.com/)前往下载本地库

下载完成直接执行安装即可。

![image-20250815164634188](图片/image-20250815164634188.png)

2.配置application.yml,选择需要监听的网卡



```yaml
http:
  pacp:
    enable: true
    interface-index: 5 # 选择监听的网卡
```



## Linux



### 
