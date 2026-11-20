import { getDatabase } from '../../../utils/databaseAdapter.js';

export async function onRequest(context) {
    // Contents of context object
    const {
      request, // same as existing Worker API
      env, // same as existing Worker API
      params, // if filename includes [id] or [[path]]
      waitUntil, // same as ctx.waitUntil in existing Worker API
      next, // used for middleware or to fetch assets
      data, // arbitrary space for passing data between middlewares
    } = context;
    
    try {
        // 前端用同站 fetch POST 调本接口；跨站表单 POST 无需 Token 就能借 Cookie 触发，
        // 因此做同站检查（见 delete/[[path]].js 的说明）：跨站信号拒绝，无信号放行。
        const forbidden = rejectCrossSiteRequest(request);
        if (forbidden) return forbidden;

        const db = getDatabase(env);
        let list = await db.get("manage@blockipList");
        if (list == null) {
            list = [];
        } else {
            list = list.split(",");
        }

        //从请求body中获取要block的ip
        const ip = await request.text();
        if (ip == null || ip == "") {
            return new Response('Error: Please input ip', { status: 400 });
        }

        //将ip添加到list中
        list.push(ip);
        await db.put("manage@blockipList", list.join(","));
        return new Response('Add ip to block list successfully', { status: 200 });
    } catch (e) {
        return new Response('Add ip to block list failed', { status: 500 });
    }
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
    return new Response('Cross-site request forbidden', { status: 403 });
}