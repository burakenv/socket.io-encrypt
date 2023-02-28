const CryptoJS = require("crypto-js");
const {
  emit,
  on,
  off,
  removeEventListener,
  removeListener,
} = require("./symbol");
const reservedEvents = require("./reserved-events");

module.exports = (secret) => (socket, next) => {
  const handlers = new WeakMap();

  const encrypt = (args) => {
    const encrypted = [];
    let ack;
    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (i === args.length - 1 && typeof arg === "function") {
        ack = arg;
      } else {
        encrypted.push(
          CryptoJS.AES.encrypt(JSON.stringify(arg), secret).toString()
        );
      }
    }
    if (!encrypted.length) return args;
    args = [{ encrypted }];
    if (ack) args.push(ack);
    console.log("encrypted", args);
    return args;
  };

  const decrypt = (encrypted) => {
    try {
      return encrypted.map((item) =>
        JSON.parse(
          CryptoJS.AES.decrypt(item, secret).toString(CryptoJS.enc.Utf8)
        )
      );
    } catch (e) {
      const error = new Error(
        `Couldn't decrypt. Wrong secret used on client or invalid data sent. (${e.message})`
      );
      error.code = "ERR_DECRYPTION_ERROR";
      throw error;
    }
  };

  socket[emit] = socket.emit;
  socket[on] = socket.on;
  socket[off] = socket.off;
  socket[removeEventListener] = socket.removeEventListener;
  socket[removeListener] = socket.removeListener;

  socket.emit = (event, ...args) => {
    if (reservedEvents.includes(event)) return socket[emit](event, ...args);
    console.log("encrypt", args);
    return socket[emit](event, ...encrypt(args));
  };

  socket.on = (event, handler) => {
    if (reservedEvents.includes(event)) return socket[on](event, handler);

    const newHandler = function (...args) {
      if (args[0] && args[0].encrypted) {
        try {
          console.log("decrypt", args);
          args = decrypt(args[0].encrypted);
        } catch (error) {
          socket[emit]("error", error);
          return;
        }
      }
      return handler.call(this, ...args);
    };

    handlers.set(handler, newHandler);
    return socket[on](event, newHandler);
  };

  socket.off = (event, handler) => {
    if (reservedEvents.includes(event)) return socket[off](event, handler);

    const properHandler = handlers.get(handler);
    if (properHandler) {
      handlers.delete(handler);
      return socket[off](event, properHandler);
    }

    return socket[off](event, handler);
  };

  socket.removeEventListener = (event, handler) => {
    return socket.off(event, handler);
  };

  socket.removeListener = (event, handler) => {
    return socket.off(event, handler);
  };

  if (next) next();
  return socket;
};
