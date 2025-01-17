import HTML from "./login-html";
import Static from "./static";
const QRCode = require("qrcode-svg");
import WXBizMsgCrypt from "./WXBizMsgCrypt";
import { XMLParser, XMLBuilder } from "fast-xml-parser";

class WxAPI {
	#TicketSize = 32;
	#TicketPrefix = "TinWxApiToken-";
	constructor(request, env) {
		this.args = Object.fromEntries(new URL(request.url).searchParams);
		this.request = request;
		this.ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "1.1.1.1";

		this.AppId = env.AppID;
		this.Token = env.AppToken;
		this.AesKey = env.AppAesKey;
		this.AppSecret = env.AppSecret;
		this.AesModeOn = env.AesMode === "ON";
		this.InitAuth = env.InitAuth;
		this.AllowOrigin = env.AllowOrigin;

		this.AI = env.AI;
		this.DB = env.DB;
		this.LIMIT = env.RATE_LIMITER;

		this.cryptor = new WXBizMsgCrypt(this.AesKey, this.AppId);
	}

	#restResp(data) {
		const resp = Response.json(data);
		resp.headers.set("Access-Control-Allow-Origin", this.AllowOrigin);
		return resp;
	}

	////////////////////////////////////////////////// = Root = //////////////////////////////////////////////////
	#encryptAes(replyStr) {
		// 加密回复给微信服务器的内容，输入为发送给微信服务器的[xml]字符串内容，返回可直接发送给微信服务器的已加密字符串
		const nonce = WXBizMsgCrypt.randStr(7, "0123456789");
		const timestamp = Math.floor(Date.now() / 1000).toString();
		const encryptedReply = this.cryptor.encrypt(replyStr);
		const msgSignatureReply = WXBizMsgCrypt.sha1(timestamp, nonce, this.cryptor.Token, encryptedReply);
		const xmlReplyOuter = {
			xml: {
				Encrypt: encryptedReply,
				MsgSignature: msgSignatureReply,
				TimeStamp: timestamp,
				Nonce: nonce
			}
		};
		return new XMLBuilder().build(xmlReplyOuter);
	}

	#doRootSubscribe(xmlMsg) {
		const xmlReply = {
			xml: {
				ToUserName: xmlMsg.FromUserName,
				FromUserName: xmlMsg.ToUserName,
				CreateTime: Math.floor(Date.now() / 1000).toString(),
				MsgType: "text",
				Content: "[你好呀~] 感谢关注TinAI生态"
			}
		};
		return new XMLBuilder().build(xmlReply);
	}

	async #doRootText(xmlMsg) {
		let content;
		try {
			content = (await this.AI.run("@cf/qwen/qwen1.5-0.5b-chat", { prompt: xmlMsg.Content })).response
		} catch (e) {
			console.log(e);
			content = "啊哦，对面被你问宕机了~";
		}
		const xmlReply = {
			xml: {
				ToUserName: xmlMsg.FromUserName,
				FromUserName: xmlMsg.ToUserName,
				CreateTime: Math.floor(Date.now() / 1000).toString(),
				MsgType: "text",
				Content: content
			}
		};
		return new XMLBuilder().build(xmlReply);
	}

	async #doRootScan(xmlMsg) {
		const raw = xmlMsg.ScanCodeInfo.ScanResult, ticket = raw.substring(this.#TicketPrefix.length);
		let content = `emmm~，看起来不像我认识的登录二维码：\n${raw}`;
		if (raw.startsWith(this.#TicketPrefix) && ticket.length === this.#TicketSize) {
			const ticketKey = `_Ticket_${ticket}`;
			const ok = (await this.DB.get(ticketKey)) === null;
			if (ok) {
				await this.DB.put(ticketKey, xmlMsg.FromUserName, { expirationTtl: 60 });
				content = "恭喜你，登录成功！";
			} else {
				content = "[!警告!] 非法访问";
			}
		}

		const xmlReply = {
			xml: {
				ToUserName: xmlMsg.FromUserName,
				FromUserName: xmlMsg.ToUserName,
				CreateTime: Math.floor(Date.now() / 1000).toString(),
				MsgType: "text",
				Content: content
			}
		};
		return new XMLBuilder().build(xmlReply);
	}

	async #doRootCode(xmlMsg) {
		const uidKey = `_Uid_${xmlMsg.FromUserName}`;
		let code = await this.DB.get(uidKey);
		if (code === null) {
			code = WXBizMsgCrypt.randStr(6, "1234566678888999");
			while ((await this.DB.get(`_Code_${code}`)) !== null) {
				code = WXBizMsgCrypt.randStr(6, "1234566678888999");
			}
			await this.DB.put(`_Code_${code}`, xmlMsg.FromUserName, { expirationTtl: 300 });
			await this.DB.put(uidKey, code, { expirationTtl: 300 });
		}

		const xmlReply = {
			xml: {
				ToUserName: xmlMsg.FromUserName,
				FromUserName: xmlMsg.ToUserName,
				CreateTime: Math.floor(Date.now() / 1000).toString(),
				MsgType: "text",
				Content: `您的登录验证码是：${code}\n该验证码5分钟内有效`
			}
		};
		return new XMLBuilder().build(xmlReply);
	}

	#doRootTextOnly(xmlMsg, text) {
		const xmlReply = {
			xml: {
				ToUserName: xmlMsg.FromUserName,
				FromUserName: xmlMsg.ToUserName,
				CreateTime: Math.floor(Date.now() / 1000).toString(),
				MsgType: "text",
				Content: text || "[叮叮~] 当前仅支持文字消息哈"
			}
		};
		return new XMLBuilder().build(xmlReply);
	}

	#verifyPain() {
		const nonce = this.args.nonce;
		const timestamp = this.args.timestamp;
		const signature = this.args.signature;
		const hashcode = WXBizMsgCrypt.sha1(this.Token, timestamp, nonce);
		return hashcode === signature;
	}

	#verifyAes(xmlAesMsg) {
		const nonce = this.args.nonce;
		const timestamp = this.args.timestamp;
		const msgSignature = this.args.msg_signature;
		const sha1 = WXBizMsgCrypt.sha1(timestamp, nonce, xmlAesMsg.Encrypt, this.Token);
		return sha1 === msgSignature;
	}

	async #doRootAction(xmlMsg) {
		if (xmlMsg.MsgType === "event") {
			const { success } = await this.LIMIT.limit({ key: `WxMsg_${xmlMsg.FromUserName}` });
			if (!success) {
				return this.#doRootTextOnly(xmlMsg, `慢一点！慢一点！要坚持不住啦~\n[id: ${WXBizMsgCrypt.randStr(4)}]`);
			}
			if (xmlMsg.Event === "subscribe") {
				return this.#doRootSubscribe();
			} else if (xmlMsg.Event === "CLICK") {
				return await this.#doRootCode(xmlMsg);
			} else if (xmlMsg.Event === "scancode_waitmsg") {
				return await this.#doRootScan(xmlMsg);
			}
		} else if (xmlMsg.MsgType === "text") {
			return await this.#doRootText(xmlMsg);
		}
		return this.#doRootTextOnly(xmlMsg);
	}

	async #rootActionAes() {
		const xmlParser = new XMLParser();
		try {
			const strAesMsg = await this.request.text();
			const xmlAesMsg = xmlParser.parse(strAesMsg).xml;
			if (!this.#verifyAes(xmlAesMsg)) {
				return "Signature Failed";
			}
			const strMsg = this.cryptor.decrypt(xmlAesMsg.Encrypt);
			const xmlMsg = xmlParser.parse(strMsg).xml;
			const strReply = this.#doRootAction(xmlMsg);
			return this.#encryptAes(strReply);
		} catch (e) {
			console.log("Root Aes Action:", e);
			return "Failed";
		}
	}

	async #rootActionPlain() {
		const xmlParser = new XMLParser();
		try {
			if (!this.#verifyPain()) {
				return "Signature Failed";
			}
			const strMsg = await this.request.text();
			const xmlMsg = xmlParser.parse(strMsg).xml;
			return this.#doRootAction(xmlMsg);
		} catch (e) {
			console.log("Root Plain Action:", e);
			return "Failed";
		}
	}

	async handleRoot() {
		let reply = "Method Not Allowed";
		if (this.request.method === "POST") {
			reply = await (this.AesModeOn ? this.#rootActionAes() : this.#rootActionPlain());
		} else if (this.request.method === "GET") {
			reply = this.#verifyPain() ? this.args.echostr || "Success" : "Failed";
		}
		return new Response(reply);
	}

	////////////////////////////////////////////////// = OAuth Login = //////////////////////////////////////////////////
	async handleQrcode() {
		if (this.request.method !== "GET") {
			return this.#restResp({ code: 400, msg: "Method Not Allowed" });
		}
		if (this.args.ticket === undefined) {
			return this.#restResp({ code: 400, msg: "Param Error" });
		}
		const qr = new QRCode({ content: this.args.ticket, join: true, pretty: false, padding: 1 });
		return new Response(qr.svg(), { headers: { "Content-Type": "image/svg+xml" } });
	}

	async handleOauth() {
		if (this.request.method === "GET") {
			return new Response(HTML, {
				status: 200,
				headers: {
					"content-type": "text/html"
				}
			});
		} else if (this.request.method === "POST") {
			const { success } = await this.LIMIT.limit({ key: `OAuth_${this.ip}` });
			if (!success) {
				return this.#restResp({ code: 400, msg: "Rate Limited" });
			}
			try {
				const payload = await this.request.json();
				if (payload.type === "ticket") {
					const ipKey = `_IP_Ticket_${this.ip}`;
					let ticket = await this.DB.get(ipKey);
					if (ticket === null) {
						ticket = WXBizMsgCrypt.randStr(this.#TicketSize);
						while ((await this.DB.get(`_Ticket_${ticket}`)) !== null) {
							ticket = WXBizMsgCrypt.randStr(this.#TicketSize);
						}
						await this.DB.put(ipKey, ticket, { expirationTtl: 300 });
					}
					return this.#restResp({ code: 200, data: `${this.#TicketPrefix}${ticket}` });
				} else if (payload.type === "login") {
					const codeKey = `_Code_${payload.data}`;
					const uid = await this.DB.get(codeKey);
					if (uid === null) {
						return this.#restResp({ code: 400, msg: "验证码错误或已过期" });
					}
					const uidKey = `_Uid_${uid}`;
					await this.DB.delete(codeKey);
					await this.DB.delete(uidKey);
					return this.#restResp({ code: 200, msg: "登录成功", data: uid });
				} else if (payload.type === "query") {
					const ticket = payload.data.substring(this.#TicketPrefix.length);
					const value = await this.DB.get(`_Ticket_${ticket}`);
					if (value === null) {
						return this.#restResp({ code: 300, msg: "waiting" });
					}
					await this.DB.delete(`_IP_Ticket_${this.ip}`);
					await this.DB.delete(`_Ticket_${ticket}`);
					return this.#restResp({ code: 200, data: value });
				}
				return this.#restResp({code: 400, msg: "Param Error"});
			} catch (e) {
				console.log(e);
				return this.#restResp({ code: 400, msg: "Param Error" });
			}
		}
		return this.#restResp({ code: 400, msg: "Method Not Allowed" });
	}

	////////////////////////////////////////////////// = Init = //////////////////////////////////////////////////
	async #get_access_token() {
		const key = `_SYS_AccessToken`;
		const token = await this.DB.get(key);
		if (token !== null) {
			return { success: true, token: token };
		}
		const url = `https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=${this.AppId}&secret=${this.AppSecret}`;
		try {
			const resp = await fetch(url);
			if (!resp.ok) {
				return { success: false, message: resp.statusText };
			}
			const data = await resp.json();
			if (data.access_token === undefined) {
				return { success: false, message: JSON.stringify(data) };
			}
			await this.DB.put(key, data.access_token, {
				expirationTtl: data.expires_in,
			});
			return { success: true, token: data.access_token };
		} catch (error) {
			return { success: false, message: error.message };
		}
	}

	async handleInit() {
		if (this.args.auth !== this.InitAuth) {
			return this.#restResp({ code: 400, msg: "Auth Failed" });
		}
		const access = await this.#get_access_token();
		if (!access.success) {
			return this.#restResp(access.message);
		}
		const url = `https://api.weixin.qq.com/cgi-bin/menu/create?access_token=${access.token}`;
		const payload = {
			button: [
				{
					"type": "click",
					"name": "验证码登录",
					"key": "Login_By_Code"
				},
				{
					"type": "scancode_waitmsg",
					"name": "扫码登录",
					"key": "Login_By_Scan"
				}
			]
		};
		const resp = await fetch(
			url,
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(payload)
			}
		);
		if (!resp.ok) {
			return this.#restResp({ code: 500, msg: resp.statusText });
		}
		return this.#restResp({ code: 200, msg: await resp.json() });
	}
}

export default {
	async fetch(request, env) {
		const api = new WxAPI(request, env);
		const url = new URL(request.url);
		const path_arr = url.pathname.substring(1).split("/");

		if (path_arr[0] === "") {
			return api.handleRoot();
		} else if (path_arr[0] === "favicon.ico") {
			return new Response(Static.Icon, { headers: { "Content-Type": "image/svg+xml" } });
		} else if (path_arr[0] === "wx-follow") {
			return new Response(Static.TinAI, { headers: { "Content-Type": "image/svg+xml" } });
		} else if (path_arr[0] === "qrcode") {
			return api.handleQrcode();
		} else if (path_arr[0] === "oauth") {
			return api.handleOauth();
		} else if (path_arr[0] === "init") {
			return api.handleInit();
		}
		return Response.json({ code: 400, msg: "Not found" });
	}
};
