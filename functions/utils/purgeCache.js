import { fetchOthersConfig } from "./sysConfig";

/**
 * 清除 Cloudflare CDN 缓存
 * @param {Object} env - 环境变量
 * @param {string} cdnUrl - 要清除缓存的 URL
 * @returns {Promise<boolean>} true=已清除或无需清除（未配置），false=清除失败（调用方可据此处理）
 */
export async function purgeCFCache(env, cdnUrl) {
    try {
        // 读取其他设置（局部变量，避免并发请求互相覆盖）
        const othersConfig = await fetchOthersConfig(env);
        const cfZoneId = othersConfig.cloudflareApiToken.CF_ZONE_ID;
        const cfEmail = othersConfig.cloudflareApiToken.CF_EMAIL;
        const cfApiKey = othersConfig.cloudflareApiToken.CF_API_KEY;

        // 如果没有配置Cloudflare API，跳过缓存清除
        if (!cfZoneId || !cfEmail || !cfApiKey) {
            return true;
        }

        // 清除CDN缓存：用 JSON.stringify 组装 body，避免 URL 含引号时拼出非法 JSON
        const options = {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-Auth-Email': `${cfEmail}`, 'X-Auth-Key': `${cfApiKey}`},
            body: JSON.stringify({ files: [cdnUrl] })
        };
        const response = await fetch(`https://api.cloudflare.com/client/v4/zones/${ cfZoneId }/purge_cache`, options);
        if (!response.ok) {
            console.error('Failed to purge CF cache: Cloudflare API returned', response.status);
            return false;
        }
        return true;
    } catch (error) {
        console.error('Failed to purge CF cache:', error.message || error);
        return false;
    }
}

export async function purgeRandomFileListCache(origin, ...dirs) {
    try {
        const cache = caches.default;
        // cache.delete有bug，通过写入一个max-age=0的response来清除缓存
        const nullResponse = new Response(null, {
            headers: { 'Cache-Control': 'max-age=0' },
        });

        for (const dir of dirs) {
            await cache.put(`${origin}/api/randomFileList?dir=${dir}`, nullResponse);
        }
    } catch (error) {
        console.error('Failed to clear randomFileList cache:', error);
    }
}

export async function purgePublicFileListCache(origin, ...dirs) {
    try {
        const cache = caches.default;
        // cache.delete有bug，通过写入一个max-age=0的response来清除缓存
        const nullResponse = new Response(null, {
            headers: { 'Cache-Control': 'max-age=0' },
        });

        for (const dir of dirs) {
            // 清除递归和非递归两种缓存
            await cache.put(`${origin}/api/publicFileList?dir=${dir}&recursive=false`, nullResponse);
            await cache.put(`${origin}/api/publicFileList?dir=${dir}&recursive=true`, nullResponse);
        }
    } catch (error) {
        console.error('Failed to clear publicFileList cache:', error);
    }
}
