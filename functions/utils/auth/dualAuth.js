/**
 * 双重鉴权工具
 * 基于统一认证核心，管理端和用户端认证一次完成
 */

import { authenticate, AUTH_SCOPE } from './authCore.js';

/**
 * 双重鉴权检查：管理端或用户端任意一个通过即可
 * @param {Object} env - 环境变量
 * @param {URL} url - 请求的URL
 * @param {Request} request - 请求对象
 * @param {Object} [options] - 可选项
 * @param {string|null} [options.requiredPermission=null] - API Token 调用本端点所需的权限；
 *        只约束 Token 路径，会话/凭据路径不受影响。不传则任何有效 Token 都可通过（保持旧行为）。
 * @param {'admin'|'user'|'either'} [options.authScope='either'] - 认证范围
 * @returns {Promise<{authorized: boolean, authType: string|null, configError?: boolean}>}
 */
export async function dualAuthCheck(env, url, request, options = {}) {
    return await authenticate({
        env,
        request,
        url,
        requiredPermission: options.requiredPermission ?? null,
        authScope: options.authScope ?? AUTH_SCOPE.EITHER,
    });
}
