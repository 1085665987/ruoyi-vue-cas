# 若依vue前后端分离单点登录和登出

#### 介绍
若依vue前后端分离单点登录和登出。

#### 软件架构
ruoyi-vue3单应用版本+cas5.3.16+SpringBoot2.6.12+vite3+element-plus+mybatis-plus

#### 使用方法
1、全局搜索sso.example.com全部换成自己的单点服务端地址。<br />
2、全局搜索172.29.28.121全部换成自己电脑的ip地址。<br />
3、配置自己的MySQL和Redis数据库。<br />
4、配置cas单点服务器跨域，配置如下：<br />

```
cas.http-web-request.cors.enabled=false
cas.http-web-request.cors.allow-credentials=false
cas.http-web-request.cors.allow-origins[0]=
cas.http-web-request.cors.allow-methods[0]=*
cas.http-web-request.cors.allow-headers[0]=*
cas.http-web-request.cors.max-age=3600
cas.http-web-request.cors.exposed-headers[0]=
```
#### 参考资料
1、本项目是参考了以下项目后做了部分代码的修改和新增，以下项目并没有做单点登出。<br />
2、参考项目地址：https://gitee.com/ggxforever/RuoYi-Vue-cas
