// API Token权限验证工具函数
import { getTokenData } from '../../api/manage/apiTokens.js';
import { isExpired } from './tokenExpiration.js';

/**
 * 验证API Token权限
 * @param {Request} request - 请求对象
 * @param {Object} db - 数据库适配器
 * @param {string} requiredPermission - 需要的权限 ('upload', 'delete', 'list')
 * @returns {Promise<{valid: boolean, error?: string}>}
 */
export async function validateApiToken(request, db, requiredPermission) {
    const authHeader = request.headers.get('Authorization');
    
    if (!authHeader) {
        return { valid: false, error: '缺少Authorization头' };
    }

    let token;
    
    // 支持两种格式: "Bearer token" 或 "token"
    if (authHeader.startsWith('Bearer ')) {
        token = authHeader.substring(7);
    } else {
        token = authHeader;
    }

    if (!token) {
        return { valid: false, error: '无效的Token格式' };
    }

    // 获取完整Token数据
    const tokenData = await getTokenData(db, token);
    
    if (!tokenData) {
        return { valid: false, error: '无效的Token' };
    }

    // 检查Token是否已过期
    if (isExpired(tokenData.expiresAt)) {
        return { valid: false, error: 'Token 已过期' };
    }

    // 检查权限，如果不需要特定权限（requiredPermission为null），则只要token有效就通过
    // permissions 损坏（非数组）时直接拒绝，避免 .includes 抛错或字符串子串匹配
    if (requiredPermission !== null) {
        if (!Array.isArray(tokenData.permissions) || !tokenData.permissions.includes(requiredPermission)) {
            return { valid: false, error: `缺少${requiredPermission}权限` };
        }
    }

    return { valid: true };
}
