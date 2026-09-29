"use strict";

const HOP_BY_HOP_HEADERS = new Set([
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
]);

module.exports = async function proxy(req, res, routePath) {
    let origin;
    try {
        origin = new URL(process.env.APP_ORIGIN);
        if (origin.protocol !== "http:" && origin.protocol !== "https:") {
            throw new Error("APP_ORIGIN must use HTTP or HTTPS");
        }
    } catch {
        res.statusCode = 500;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("Set APP_ORIGIN to the URL of the deployed C++ service.");
        return;
    }

    const requestUrl = new URL(req.url, "http://vercel.local");
    origin.pathname = routePath;
    origin.search = requestUrl.search;

    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
        if (value !== undefined && !HOP_BY_HOP_HEADERS.has(name.toLowerCase())) {
            headers.set(name, Array.isArray(value) ? value.join(", ") : value);
        }
    }

    const options = {
        method: req.method,
        headers,
        redirect: "manual",
    };
    if (req.method !== "GET" && req.method !== "HEAD") {
        const chunks = [];
        for await (const chunk of req) {
            chunks.push(chunk);
        }
        options.body = Buffer.concat(chunks);
    }

    try {
        const upstream = await fetch(origin, options);
        res.statusCode = upstream.status;

        for (const [name, value] of upstream.headers) {
            const lowerName = name.toLowerCase();
            if (!HOP_BY_HOP_HEADERS.has(lowerName) && lowerName !== "content-encoding") {
                res.setHeader(name, value);
            }
        }
        const cookies = upstream.headers.getSetCookie?.();
        if (cookies?.length) {
            res.setHeader("Set-Cookie", cookies);
        }

        if (req.method === "HEAD" || upstream.status === 204 || upstream.status === 304) {
            res.end();
        } else {
            res.end(Buffer.from(await upstream.arrayBuffer()));
        }
    } catch (error) {
        console.error("Vercel upstream request failed:", error);
        res.statusCode = 502;
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.end("The application backend is unavailable.");
    }
};