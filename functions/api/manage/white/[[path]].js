import { purgeCFCache, purgeRandomFileListCache, purgePublicFileListCache } from "../../../utils/purgeCache";
import { addFileToIndex } from "../../../utils/indexManager.js";
import { getDatabase } from "../../../utils/databaseAdapter.js";
import { cleanPersistedMetadata } from "../../../utils/metadata/metadataSecurity.js";

export async function onRequest(context) {
    // Contents of context object
    const {
      request, // same as existing Worker API
      env, // same as existing Worker API
      params, // if filename includes [id] or [[path]]
      waitUntil, // same as ctx.waitUntil in existing Worker API
    } = context;

    // 组装 CDN URL
    const url = new URL(request.url);

    // 前端是预编译 bundle，仍用 GET 调加白接口，因此不禁 GET，改为同站检查
    // （见 delete/[[path]].js 的说明）：跨站信号拒绝，无信号放行。
    const forbidden = rejectCrossSiteRequest(request);
    if (forbidden) return forbidden;

    if (params.path) {
      params.path = String(params.path).split(',').join('/');
    }
    const cdnUrl = `https://${url.hostname}/file/${params.path}`;

    // 解码params.path
    params.path = decodeURIComponent(params.path);

    //read the metadata
    const db = getDatabase(env);
    const value = await db.getWithMetadata(params.path);

    // 记录不存在时直接 404，不再对空记录写 ListType 导致 500 崩溃。
    if (!value || !value.metadata) {
      return new Response(JSON.stringify({ success: false, error: 'File not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    //change the metadata
    value.metadata.ListType = "White"
    const metadata = cleanPersistedMetadata(value.metadata);
    await db.put(params.path, value.value, {metadata});
    const info = JSON.stringify({ success: true, listType: metadata.ListType });

    // 清除CDN缓存
    await purgeCFCache(env, cdnUrl);

    // 清除 randomFileList 等API缓存
    const normalizedFolder = params.path.split('/').slice(0, -1).join('/');
    await purgeRandomFileListCache(url.origin, normalizedFolder);
    await purgePublicFileListCache(url.origin, normalizedFolder);

    // 更新索引
    waitUntil(addFileToIndex(context, params.path, metadata));

    return new Response(info);
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
    return new Response(JSON.stringify({ success: false, error: 'Cross-site request forbidden' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
    });
}
