/**
 * 外链 URL 的 SSRF 校验（P1-30）。
 *
 * 逻辑复用自 functions/api/fetchRes.js 的 isPrivateHostname（该文件不属于
 * 本组，只读不改），并补上它没有的尾加点处理：判断前先去掉 hostname 末尾
 * 的 `.`，否则 `http://localhost./` 会绕过检查。
 * 注意：这里只校验 URL 本身，不跟随重定向；fetch 默认跟随的重定向目标
 * 仍需调用方另外处理。
 */

function isPrivateHostname(hostname) {
    if (!hostname) return true;
    let h = hostname.toLowerCase();
    // 判断前去掉末尾的点：localhost. 与 localhost 是同一主机
    h = h.replace(/\.+$/, '');
    if (h.startsWith('[') && h.endsWith(']')) {
        h = h.slice(1, -1);
    }

    if (h === 'localhost' || h === 'ip6-localhost' || h === 'ip6-loopback') return true;
    if (h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return true;

    if (h === 'metadata.google.internal' || h === 'metadata.goog') return true;

    const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipv4) {
        const [a, b] = [parseInt(ipv4[1], 10), parseInt(ipv4[2], 10)];
        if (a === 10) return true;
        if (a === 127) return true;
        if (a === 0) return true;
        if (a === 169 && b === 254) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 168) return true;
        if (a === 100 && b >= 64 && b <= 127) return true;
        if (a >= 224) return true;
        return false;
    }

    if (h.includes(':')) {
        if (h === '::' || h === '::1') return true;
        if (h.startsWith('fe80:') || h.startsWith('fe80::')) return true;
        if (h.startsWith('fc') || h.startsWith('fd')) return true;
        const mapped = h.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
        if (mapped) return isPrivateHostname(mapped[1]);
        return false;
    }

    return false;
}

export { isPrivateHostname };

/**
 * 校验外链 URL：只允许 http(s)、不带内嵌凭据、主机不是内网/保留地址。
 * @returns {{ok: true, url: URL}|{ok: false, error: string}}
 */
export function validateExternalUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
        return { ok: false, error: 'Invalid URL' };
    }
    let parsed;
    try {
        parsed = new URL(rawUrl);
    } catch (e) {
        return { ok: false, error: 'Invalid URL' };
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return { ok: false, error: 'Only http(s) URLs are allowed' };
    }
    if (parsed.username || parsed.password) {
        return { ok: false, error: 'Credentials in URL are not allowed' };
    }
    if (isPrivateHostname(parsed.hostname)) {
        return { ok: false, error: 'Access to internal addresses is not allowed' };
    }
    return { ok: true, url: parsed };
}

export function isSafeExternalUrl(rawUrl) {
    return validateExternalUrl(rawUrl).ok;
}
