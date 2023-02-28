const crypto = require("crypto");
const { emit, on, off, removeEventListener, removeListener } = require('./symbol');
const reservedEvents = require('./reserved-events');

module.exports = (secret) => (socket, next) => {
  const handlers = new WeakMap();

  const generateIV = (key) => {
    const sha256 = crypto
      .createHash("sha256")
      .update(key)
      .digest("hex")
      .toString();
    const md5 = crypto.createHash("md5").update(sha256).digest("hex").toString();
    return md5.substring(0, 16);
  };

  const ENC_KEY = secret;
  const IV = generateIV(secret);

  const encrypt = (val) => {
    let cipher = crypto.createCipheriv("aes-256-cbc", ENC_KEY, IV);
    let encrypted = cipher.update(val, "utf8", "base64");
    encrypted += cipher.final("base64");
    return encrypted;
  };

  const decrypt = (encrypted) => {
    let decipher = crypto.createDecipheriv("aes-256-cbc", ENC_KEY, IV);
    let decrypted = decipher.update(encrypted, "base64", "utf8");
    return decrypted + decipher.final("utf8");
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

    const newHandler = function(...args) {
      if (args[0] && args[0].encrypted) {
        try {
          args = decrypt(args[0].encrypted);
        } catch (error) {
          socket[emit]('error', error);
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
  }

  socket.removeEventListener = (event, handler) => {
    return socket.off(event, handler);
  }

  socket.removeListener = (event, handler) => {
    return socket.off(event, handler);
  }

  if (next) next();
  return socket;
};
