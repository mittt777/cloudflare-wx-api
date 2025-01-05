class TinWxLogin {
  #on_loop = this.#detaultHandler;
  #on_qrcode = this.#detaultHandler;
  #on_success = this.#detaultHandler;
  #on_failure = this.#detaultHandler;

  constructor(url) {
    const ws = new WebSocket(url);
    let close_call = true;
    if (!ws) {
      this.#on_failure("Server didn't accept ws");
    }
    ws.addEventListener("message", ({ data }) => {
      try {
        const resp = JSON.parse(data);
        if (resp.code === 300) {
          this.#on_loop(resp.msg);
        } else if (resp.code === 100) {
          this.#on_qrcode(resp.data);
        } else if (resp.code === 400) {
          close_call = false;
          this.#on_failure(resp.msg);
        } else if (resp.code === 200) {
          close_call = false;
          this.#on_success(resp.data);
        } else {
          close_call = false;
          this.#on_failure(`unknown response code: ${resp.code}`);
        }
      } catch (e) {
        close_call = false;
        this.#on_failure(e);
      }
    });
    ws.addEventListener("close", () => {
      if (close_call) {
        this.#on_failure("Server closed your connection");
      }
    });
  }
  #detaultHandler(...args) {
    console.log(...args);
  }
  onQrcode(callback) {
    this.#on_qrcode = callback || this.#detaultHandler;
    return this;
  }
  onSuccess(callback) {
    this.#on_success = callback || this.#detaultHandler;
    return this;
  }
  onFailure(callback) {
    this.#on_failure = callback || this.#detaultHandler;
    return this;
  }
  onLoop() {
    this.#on_loop = callback || this.#detaultHandler;
    return this;
  }
}

function qrcodeTest() {
  const tinWxLogin = new TinWxLogin("wss://your.domain.com/ws");
  tinWxLogin.onQrcode(url => {
    window.open(url);
  }).onSuccess(uid => {
    console.log(`Login success: ${uid}`);
  }).onFailure(err => {
    console.log(err);
  });
}

function codeTest() {
  fetch(
    "https://your.domain.com/login",
    {
      method: "POST",
      body: "112233"
    }
  ).then(res => res.json()).then(res => {
    console.log(res);
  });
}

// qrcodeTest();
// codeTest();