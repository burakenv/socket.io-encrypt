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

  const generateIV = (key) => {
    const sha256 = CryptoJS.SHA256(key).toString();
    const md5 = CryptoJS.MD5(sha256).toString();
    const iv = md5.substring(0, 16);
    return CryptoJS.enc.Hex.parse(iv);
  };

  const ENC_KEY = CryptoJS.enc.Hex.parse(secret);
  const IV = generateIV(secret);

  const encrypt = (val) => {
    return CryptoJS.AES.encrypt(val, ENC_KEY, {
      iv: IV,
    }).toString();
  };

  const decrypt = (encrypted) => {
    CryptoJS.AES.decrypt(encrypted, key, {
      iv: IV,
    }).toString(CryptoJS.enc.Utf8);
  };

  socket[emit] = socket.emit;
  socket[on] = socket.on;
  socket[off] = socket.off;
  socket[removeEventListener] = socket.removeEventListener;
  socket[removeListener] = socket.removeListener;

  socket.emit = (event, ...args) => {
    if (reservedEvents.includes(event)) return socket[emit](event, ...args);

    return socket[emit](event, ...encrypt(args));
  };

  socket.on = (event, handler) => {
    if (reservedEvents.includes(event)) return socket[on](event, handler);

    const newHandler = function (...args) {
      if (args[0] && args[0].encrypted) {
        try {
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
