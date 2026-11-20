/**
 * 远程资源代理读取 API
 * 负责在鉴权后拉取请求体中指定 URL 的资源并透传响应内容
 */
import { dualAuthCheck } from '../utils/auth/dualAuth.js';

const IS_NODE_RUNTIME = typeof process !== 'undefined' && Boolean(process.versions?.node);

// 上游拉取超时与响应体上限：防止慢速/超大上游拖垮 Worker 配额
export const FETCH_TIMEOUT_MS = 30000;
export const FETCH_MAX_BODY_BYTES = 10 * 1024 * 1024;

const HOP_BY_HOP_HEADERS = [
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade'
];

/**
 * Build response headers that are safe to send on a new proxy response.
 * Node's fetch transparently decompresses upstream bodies while retaining
 * Content-Encoding/Content-Length, so those headers must be removed there.
 *
 * @param {Headers} responseHeaders - headers returned by the upstream server
 * @returns {Headers}
 */
function createProxyHeaders(responseHeaders) {
    const headers = new Headers(responseHeaders);

    for (const name of HOP_BY_HOP_HEADERS) {
        headers.delete(name);
    }

    // 剥离上游 Set-Cookie：不让上游在图床域名下种 Cookie
    headers.delete('set-cookie');

    if (IS_NODE_RUNTIME) {
        headers.delete('content-encoding');
        headers.delete('content-length');
    }

    return headers;
}

function fetchTarget(url, signal) {
    const options = { redirect: 'manual', signal };
    if (IS_NODE_RUNTIME) {
        options.headers = { 'Accept-Encoding': 'identity' };
    }
    return fetch(url.toString(), options);
}

/**
 * 在大小上限内读完响应体，超限返回 null（调用方据此返回 413）
 * @param {ReadableStream|null} body - 上游响应体
 * @returns {Promise<Uint8Array|null>}
 */
async function readBodyWithLimit(body) {
    if (!body) return new Uint8Array(0);
    const reader = body.getReader();
    const chunks = [];
    let total = 0;
    try {
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > FETCH_MAX_BODY_BYTES) {
                try { await reader.cancel(); } catch { /* ignore */ }
                return null;
            }
            chunks.push(value);
        }
    } finally {
        try { reader.releaseLock(); } catch { /* ignore */ }
    }
    const result = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return result;
}

/**
 * Determine whether a hostname refers to a private, loopback, link-local,
 * cloud-metadata, or otherwise internal network address. Used to prevent
 * SSRF against internal services from the proxy endpoint.
 *
 * @param {string} hostname - hostname or IP literal from a parsed URL
 * @returns {boolean}
 */
function isPrivateHostname(hostname) {
    if (!hostname) return true;
    let h = hostname.toLowerCase();
    // 去掉末尾的点：localhost. / 127.0.0.1. 这类写法与不带点的等价，不能绕过检查
    h = h.replace(/\.+$/, '');
    if (!h) return true;
    // Strip IPv6 brackets
    if (h.startsWith('[') && h.endsWith(']')) {
        h = h.slice(1, -1);
    }

    // Obvious local names
    if (h === 'localhost' || h === 'ip6-localhost' || h === 'ip6-loopback') return true;
    if (h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;

    // Cloud metadata service hostnames
    if (h === 'metadata.google.internal' || h === 'metadata.goog') return true;

    // IPv4 literal check
    const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipv4) {
        const [a, b] = [parseInt(ipv4[1], 10), parseInt(ipv4[2], 10)];
        if (a === 10) return true;                              // 10.0.0.0/8
        if (a === 127) return true;                             // loopback
        if (a === 0) return true;                               // 0.0.0.0/8
        if (a === 169 && b === 254) return true;                // link-local / AWS metadata 169.254.169.254
        if (a === 172 && b >= 16 && b <= 31) return true;       // 172.16.0.0/12
        if (a === 192 && b === 168) return true;                // 192.168.0.0/16
        if (a === 100 && b >= 64 && b <= 127) return true;      // CGNAT 100.64.0.0/10
        if (a >= 224) return true;                              // multicast / reserved
        return false;
    }

    // IPv6 literal check (basic)
    if (h.includes(':')) {
        if (h === '::' || h === '::1') return true;
        if (h.startsWith('fe80:') || h.startsWith('fe80::')) return true;   // link-local
        if (h.startsWith('fc') || h.startsWith('fd')) return true;          // unique local fc00::/7
        // IPv4-mapped IPv6 (::ffff:a.b.c.d)
        const mapped = h.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
        if (mapped) return isPrivateHostname(mapped[1]);
        return false;
    }

    return false;
}

export async function onRequest(context) {
    // 获取请求体中URL的内容
    const {
        request,
        env,
        params,
        waitUntil,
        next,
        data
    } = context;

    // 双重鉴权检查：Token 调用本端点至少需要 manage 权限，
    // 任意有效 Token 不再等同管理员；管理员会话 / 用户凭据不受该权限约束。
    const url = new URL(request.url);
    const authResult = await dualAuthCheck(env, url, request, { requiredPermission: 'manage' });
    if (authResult.configError) {
        return new Response(JSON.stringify({ error: 'Security config unavailable' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' }
        });
    }
    if (!authResult.authorized) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const jsonRequest = await request.json();
    const targetUrl = jsonRequest.url;
    if (targetUrl === undefined) {
        return new Response('URL is required', { status: 400 })
    }

    // Validate the target URL to mitigate SSRF (CWE-918).
    let parsed;
    try {
        parsed = new URL(targetUrl);
    } catch (e) {
        return new Response(JSON.stringify({ error: 'Invalid URL' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // Only allow http(s); block file:, gopher:, data:, ftp:, blob:, etc.
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return new Response(JSON.stringify({ error: 'Only http(s) URLs are allowed' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // Refuse embedded credentials (used to smuggle auth into internal targets).
    if (parsed.username || parsed.password) {
        return new Response(JSON.stringify({ error: 'Credentials in URL are not allowed' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // Block private / loopback / link-local / metadata targets.
    if (isPrivateHostname(parsed.hostname)) {
        return new Response(JSON.stringify({ error: 'Access to internal addresses is not allowed' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    // Follow redirects manually so a permitted host cannot redirect us onto
    // an internal address without re-validation.
    // 整个拉取过程（含重定向）共用一个超时，超时后 fetch 抛 AbortError。
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let response;
    try {
        let currentUrl = parsed;
        response = await fetchTarget(currentUrl, controller.signal);
        let hops = 0;
        while (response.status >= 300 && response.status < 400 && response.headers.get('location') && hops < 5) {
            const next = new URL(response.headers.get('location'), currentUrl);
            if ((next.protocol !== 'http:' && next.protocol !== 'https:') ||
                next.username || next.password ||
                isPrivateHostname(next.hostname)) {
                return new Response(JSON.stringify({ error: 'Redirect to disallowed target' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            currentUrl = next;
            response = await fetchTarget(currentUrl, controller.signal);
            hops++;
        }
    } catch (error) {
        if (error && error.name === 'AbortError') {
            return new Response(JSON.stringify({ error: 'Upstream request timed out' }), {
                status: 504,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        return new Response(JSON.stringify({ error: 'Failed to fetch upstream URL' }), {
            status: 502,
            headers: { 'Content-Type': 'application/json' }
        });
    } finally {
        clearTimeout(timeoutId);
    }

    // 响应体大小上限：先看 Content-Length 快速拒绝，再流式读取中途截断。
    // 只限制大小，不限制 Content-Type（图片等正常返回不受影响）。
    const declaredLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > FETCH_MAX_BODY_BYTES) {
        return new Response(JSON.stringify({ error: 'Upstream response too large' }), {
            status: 413,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    let body;
    try {
        body = await readBodyWithLimit(response.body);
    } catch (error) {
        if (error && error.name === 'AbortError') {
            return new Response(JSON.stringify({ error: 'Upstream request timed out' }), {
                status: 504,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        return new Response(JSON.stringify({ error: 'Failed to read upstream response' }), {
            status: 502,
            headers: { 'Content-Type': 'application/json' }
        });
    }
    if (body === null) {
        return new Response(JSON.stringify({ error: 'Upstream response too large' }), {
            status: 413,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    const headers = createProxyHeaders(response.headers);
    // 空体时传 null：204/304 等状态不允许带 body，否则 Response 构造会抛错
    return new Response(body.byteLength === 0 ? null : body, {
        headers: headers,
        status: response.status
    })
}
