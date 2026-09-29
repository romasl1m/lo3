"use strict";

const proxy = require("../lib/vercel-proxy");

module.exports = (req, res) => proxy(req, res, "/");
module.exports.config = { api: { bodyParser: false } };