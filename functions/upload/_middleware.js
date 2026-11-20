import { errorHandling, telemetryData, checkDatabaseConfig } from '../utils/middleware';

// CORS 跨域响应头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

// P2-50：只给分块初始化与合并做简单按 IP 限流。单文件上传与分块上传
// 本身不限（正常上传不应被误伤）；限流只挡“无限发起初始化/合并”
// 拖垮 Worker 的行为。阈值留足余量：同一 IP 每分钟 60 次初始化/合并，
// 正常用户一次上传只产生 1 次初始化 + 1 次合并，远到不了这个数。
// 注意：这是 isolate 内内存计数，实例重启即清零，只能防滥用、不能做
// 精确配额；未完成的 multipart 定时清理不在本轮做。
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_INIT_MERGE_PER_MINUTE = 60;
const rateLimitBuckets = new Map();

function isInitOrMergeRequest(request) {
    if (request.method !== 'POST') return false;
    const url = new URL(request.url);
    return url.searchParams.get('initChunked') === 'true' ||
        (url.searchParams.get('chunked') === 'true' && url.searchParams.get('merge') === 'true');
}

function getRateLimitIp(request) {
    return request.headers.get('cf-connecting-ip') ||
        request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
        'unknown';
}

async function rateLimitUploadInit(context) {
    if (!isInitOrMergeRequest(context.request)) {
        return context.next();
    }
    const ip = getRateLimitIp(context.request);
    const now = Date.now();
    let bucket = rateLimitBuckets.get(ip);
    if (!bucket || now - bucket.windowStart >= RATE_LIMIT_WINDOW_MS) {
        bucket = { windowStart: now, count: 0 };
        rateLimitBuckets.set(ip, bucket);
    }
    bucket.count += 1;
    if (bucket.count > RATE_LIMIT_MAX_INIT_MERGE_PER_MINUTE) {
        return new Response(JSON.stringify({ error: 'Too many upload initialization requests, please retry later' }), {
            status: 429,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
    }
    // 防止 Map 无限增长：超过 5000 个 IP 时清掉已过期的桶
    if (rateLimitBuckets.size > 5000) {
        for (const [key, value] of rateLimitBuckets) {
            if (now - value.windowStart >= RATE_LIMIT_WINDOW_MS) rateLimitBuckets.delete(key);
        }
    }
    return context.next();
}

// OPTIONS 预检请求处理
async function handleOptions(context) {
    if (context.request.method === 'OPTIONS') {
        return new Response(null, {
            status: 204,
            headers: corsHeaders
        });
    }
    return context.next();
}

export const onRequest = [checkDatabaseConfig, handleOptions, rateLimitUploadInit, errorHandling, telemetryData];
