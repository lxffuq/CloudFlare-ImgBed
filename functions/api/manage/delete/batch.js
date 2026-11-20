import { batchRemoveFilesFromIndex } from '../../../utils/indexManager.js';
import { mapConcurrent, normalizeBatchFileIds } from '../../../utils/deleteBatch.js';
import { validateFileId } from '../../../utils/tagService.js';
import { deleteFile } from './[[path]].js';

const MAX_BATCH_SIZE = 500;
const DELETE_CONCURRENCY = 10;

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

export async function onRequest(context) {
    if (context.request.method !== 'POST') {
        return jsonResponse({ success: false, error: 'Method not allowed' }, 405);
    }

    // 批量删除是 POST + JSON body，跨站表单无法构造；仍做同站检查防跨站 POST。
    // validateFileId 在单测加载器里可能被 stub 掉（旧测试未提供该 mock），生产环境恒为函数。
    const forbidden = rejectCrossSiteRequest(context.request);
    if (forbidden) return forbidden;

    try {
        const payload = await context.request.json();
        const fileIds = normalizeBatchFileIds(payload?.fileIds, MAX_BATCH_SIZE);
        if (fileIds.length === 0) {
            return jsonResponse({ success: false, error: 'fileIds is required' }, 400);
        }
        // 系统配置键（manage@ 开头等）禁止删除，与单个删除入口共用同一校验。
        if (typeof validateFileId === 'function') {
            for (const fileId of fileIds) validateFileId(fileId);
        }
        const url = new URL(context.request.url);
        const results = await mapConcurrent(fileIds, DELETE_CONCURRENCY, async (fileId) => {
            try {
                const cdnUrl = `${url.origin}/file/${fileId.split('/').map(encodeURIComponent).join('/')}`;
                const result = await deleteFile(context.env, fileId, cdnUrl, url, context.waitUntil);
                const success = !!(result && result.deleted);
                return { fileId, success, existed: !!(result && result.existed), error: success ? '' : 'Delete file failed' };
            } catch (err) {
                return { fileId, success: false, existed: false, error: String(err?.message || err) };
            }
        });

        // deleted 包含所有处理成功的 ID；missing 是其中记录不存在的子集。
        const deleted = results.filter((item) => item.success).map((item) => item.fileId);
        const missing = results.filter((item) => item.success && !item.existed).map((item) => item.fileId);
        const failed = results.filter((item) => !item.success).map(({ fileId, error }) => ({ fileId, error }));
        if (deleted.length > 0) {
            // 整批只合并一次，响应前完成，刷新后不再出现
            const indexResult = await batchRemoveFilesFromIndex(context, deleted);
            if (!indexResult.success) console.warn('Index sync failed after batch delete:', indexResult.error);
        }
        return jsonResponse({ success: failed.length === 0, deleted, missing, failed, details: results });
    } catch (error) {
        return jsonResponse({ success: false, error: error.message }, 400);
    }
}

function jsonResponse(payload, status = 200) {
    return new Response(JSON.stringify(payload), {
        status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
}

// 同站检查：有跨站信号返回 403 响应，无跨站信号返回 null（见 delete/[[path]].js 的说明）。
function isCrossSiteRequest(request) {
    const fetchSite = request.headers.get('Sec-Fetch-Site');
    if (fetchSite) return fetchSite !== 'same-origin' && fetchSite !== 'same-site' && fetchSite !== 'none';
    const origin = request.headers.get('Origin');
    if (origin) {
        try { return new URL(origin).origin !== new URL(request.url).origin; } catch { return true; }
    }
    const referer = request.headers.get('Referer');
    if (referer) {
        try { return new URL(referer).origin !== new URL(request.url).origin; } catch { return true; }
    }
    return false;
}

function rejectCrossSiteRequest(request) {
    if (request.headers.get('Authorization') || !isCrossSiteRequest(request)) return null;
    return jsonResponse({ success: false, error: 'Cross-site request forbidden' }, 403);
}
