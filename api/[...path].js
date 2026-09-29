"use strict";

const proxy = require("../lib/vercel-proxy");

module.exports = (req, res) => {
    const path = req.query.path;
    const segments = Array.isArray(path) ? path : path ? [path] : [];
    return proxy(req, res, `/${segments.join("/")}`);
};
module.exports.config = { api: { bodyParser: false } };