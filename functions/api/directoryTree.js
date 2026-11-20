import { getDirectoryTree } from '../utils/indexManager';
import { dualAuthCheck } from '../utils/auth/dualAuth';
import { fetchPageConfig } from '../utils/sysConfig';

/**
 * 目录树 API 端点
 * GET /api/directoryTree
 * 
 * 查询参数：
 * - cacheTime: 可选，覆盖默认缓存时间（秒），默认 60
 * 
 * 响应：
 * - 成功：{ tree: DirectoryTreeNode }
 * - 失败：{ error: string }
 * 
 * 权限说明：
 * - 管理端鉴权成功：始终允许访问
 * - 用户端鉴权成功：仅当 showDirectorySuggestions 开启时允许访问
 */
export async function onRequestGet(context) {
    const { env, request } = context;
    const url = new URL(request.url);
    
    // 双重鉴权：用户端或管理端任意一个通过即可
    // Token 调用本端点至少需要 list 权限（不再等同管理员）
    const authResult = await dualAuthCheck(env, url, request, { requiredPermission: 'list' });
    if (authResult.configError) {
        return new Response(JSON.stringify({ error: 'Security config unavailable' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
        });
    }
    if (!authResult.authorized) {
        return new Response('Unauthorized', { status: 401 });
    }
    
    // 非管理员身份（用户端或未配置认证的匿名访问），检查 showDirectorySuggestions 设置
    if (authResult.authType !== 'admin') {
        const pageConfig = await fetchPageConfig(env);
        // 从 config 数组中查找 showDirectorySuggestions 设置
        const showDirSetting = pageConfig.config?.find(c => c.id === 'showDirectorySuggestions');
        const showDirectorySuggestions = showDirSetting?.value ?? showDirSetting?.default ?? true;
        
        if (!showDirectorySuggestions) {
            return new Response(JSON.stringify({ error: 'Directory suggestions disabled' }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }
    
    try {
        const tree = await getDirectoryTree(context);
        // cacheTime 必须是 0–3600 的整数，非法值用默认 60，避免拼出非法响应头或超长缓存
        const rawCacheTime = url.searchParams.get('cacheTime');
        let cacheTime = 60;
        if (rawCacheTime !== null) {
            const parsed = Number(rawCacheTime);
            if (Number.isFinite(parsed)) {
                cacheTime = Math.min(3600, Math.max(0, Math.trunc(parsed)));
            }
        }

        return new Response(JSON.stringify({ tree }), {
            headers: {
                'Content-Type': 'application/json',
                'Cache-Control': `private, max-age=${cacheTime}`,
                'Access-Control-Allow-Origin': '*',
            }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}
