# CloudFlare 微信服务号后台

## 实现功能
1. 自定义菜单
2. 文字消息回复: 接入 LLM 实现聊天机器人
3. 网页扫码登录
4. 微信验证码登录

## 部署
### 准备
1. 个人微信公众号
  + AppID
  + AppSecret
  + Token
  + AesKey
2. 托管到 cloudflare 的域名

### 部署流程
1. Fork该项目到自己的仓库，之后Pull到本地
2. 将`wrangler-example.toml`复制一份命名为`wrangler.toml`
3. 修改`wrangler.toml`内的关键信息，如域名、KV-ID、环境变量等
4. 安装依赖包：`npm install`
5. 部署项目：`nom run deploy`
6. 在微信公众平台将服务号的服务器地址设置为`wrangler.toml`配置的域名
7. 在微信公众平台添加cloudflare所有ip地址为白名单：[cloudflare ip 地址范围](https://www.cloudflare-cn.com/ips/)

## TODO
1. AES 加密通信，当前aes加密还存在一点小问题，不知道怎么解决，参考文档：[cloudflare web-crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)，[微信加密消息说明](https://developers.weixin.qq.com/doc/offiaccount/Message_Management/Message_encryption_and_decryption_instructions.html)
