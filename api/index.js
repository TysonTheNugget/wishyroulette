// api/index.js
const app = require('../backend');

// Normalize the path so Express sees "/init", "/poll", etc.
module.exports = (req, res) => {
  if (req.url.startsWith('/api/index')) {
    req.url = req.url.replace('/api/index', '');
  }
  return app(req, res);
};