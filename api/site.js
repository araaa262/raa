const app = require('../app');
module.exports = (req, res) => {
  const path = req.query.path;
  req.url = `/${Array.isArray(path) ? path.join('/') : (path || '')}`;
  return app(req, res);
};
