# DBMPIG  (DPDK Based Multi-stage Pipeline IPsec Gateway)

## 1. 项目功能说明

基于DPDK开发的多核并行的IPsec VPN高速网关，可以在万兆高速网络下提供接近线速的安全数据传输速率。

## 2. 网关结构设计

**功能模块设计图：**
![image](https://note.youdao.com/yws/public/resource/fdafc686c22e3ed7e47ed39fec9dd250/xmlnote/4B58C337347148CDB96E55B3817D51B0/0F6E40052A554D7E93FC491B0DE8BF63/5272)

**多核流水线设计图：**
![image](https://note.youdao.com/yws/public/resource/fdafc686c22e3ed7e47ed39fec9dd250/xmlnote/4B58C337347148CDB96E55B3817D51B0/7A0FA3658DDA453DB47E7C05CF20989C/5274)


## 3. 使用说明

- 下载DPDK16.11.3（或者更高版本，但是没经过测试）
- 配置DPDK CRYPTO加密引擎编译，参考官方文档：[DPDK 16.11 Crypto Device Drivers](http://www.dpdk.org/doc/guides-16.11/cryptodevs/aesni_mb.html)
- 编译DPDK，配置端口，大页内存等
- 编译项目：make
- 运行项目：
```
./build/load_balancer -c 0xf0 -n 4 -- -p 0x3 -u 0x2 --rx "(0,0,4),(1,0,4)" --tx "(0,5),(1,5)" --w "6,7" -h 90 -d y -f ep0.cfg
```
- 配置命令说明：
  - -p: 启动端口，采用16进制，位图配置，如0x03=0011，所以启动端口为0,1
  - -u: 外网端口，采用16进制，位图配置，如0x02=0010，所以端口1为外网端口
  - --rx: 接收队列配置，(端口，队列，核)，如(0,0,4)代表端口0的0号接收队列与核4绑定
  - --tx: 转发端口配置，（端口，核），如(0,5)代表端口0由核5负责转发
  - --w: IPsec处理核配置，如(6,7)代表6,7核为IPsec处理核，如[6,13]代表IPsec核为6,7,8,9,10,11,12,13八个核
  - -h: 代表负载均衡过程中的单核负载阈值，超过该数值为重负载节点，需要进行流迁移减轻负载
  - -f: 配置文件，配置安全规则，安全策略，路由规则等，可以参考项目中文件ep0.cfg
  - -d: 代表是否启动动态负载均衡，y代表启动，n代表关闭
