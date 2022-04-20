* CreateConnection:
  * 用户端发送一个initial(long header),等待解析server发送的 1-RTT。（注，图中有一个双向的 1-RTT 不知为何意。）注意 callback
* setConnectionReadyCallback
  * 持续监听，当收到 initial 的时候会给 1-RTT。
* closeConnection
  * 端点发送 CONNECTION_CLOSE 帧，并使自己进入 close 状态。
  * ![image-20220404090747003](C:\Users\86187\AppData\Roaming\Typora\typora-user-images\image-20220404090747003.png)
  * 在 close 状态下，对于接受到的所有包 回复  CONNECTION_CLOSE 帧。
* setConnectionCloseCallback
  * 问问棍
* createStream
  * 获取流ID
* CloseSream
  *  发送未发送的所有数据，并在最后一个stream标注FIN
* SendData
  * 填 StreamFrame
  * ？？？
* 



* quic.hh 里connection map 干嘛 sequence
* incomingmessage 手动解析收到的udpdatagram
* server incomingmessage 之后，如何找到地址回传(client 无地址) 要用带参数的
* callback 函数
* 讲一下1里面各个接口主要干了什么