/**
 * BatchRestoreChunkAPI - 分批恢复数据的 API 端点
 * 
 * 接收并写入一批文件数据到 KV
 */

import { getDatabase } from '../../../../utils/databaseAdapter.js';
import { cleanPersistedMetadata } from '../../../../utils/metadata/metadataSecurity.js';
import { batchAddFilesToIndex } from '../../../../utils/indexManager.js';
import { purgePublicFileListCache, purgeRandomFileListCache } from '../../../../utils/purgeCache.js';

// CORS 跨域响应头
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

/**
 * 创建 JSON 响应
 */
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders,
    },
  });
}

/**
 * 创建错误响应
 */
function errorResponse(message, status = 400, details = null) {
  const responseData = { success: false, error: message };
  if (details) {
    responseData.details = details;
  }
  return jsonResponse(responseData, status);
}

/**
 * 处理 POST 请求 - 恢复一批文件数据
 */
export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    // 解析请求体
    let body;
    try {
      body = await request.json();
    } catch (parseError) {
      return errorResponse('Invalid JSON in request body', 400);
    }

    // 验证请求体
    const { type, data } = body;
    
    if (!type || !['files', 'settings'].includes(type)) {
      return errorResponse('type must be "files" or "settings"', 400);
    }
    
    if (!data || typeof data !== 'object') {
      return errorResponse('data must be an object', 400);
    }

    const db = getDatabase(env);
    let restoredCount = 0;
    let failedCount = 0;
    const errors = [];

    if (type === 'files') {
      // 恢复文件数据 - 并行写入
      const restoredFiles = [];
      const filePromises = Object.entries(data).map(async ([key, fileData]) => {
        try {
          const metadata = cleanPersistedMetadata(fileData.metadata);
          if (fileData.value) {
            // 有 value 的文件（如 Telegram/Discord 分块文件）
            await db.put(key, fileData.value, {
              metadata
            });
          } else if (fileData.metadata) {
            // 只有元数据的文件
            await db.put(key, '', {
              metadata
            });
          }
          restoredFiles.push({ fileId: key, metadata });
          return { success: true };
        } catch (error) {
          return { success: false, key, error: error.message };
        }
      });

      const results = await Promise.all(filePromises);
      for (const result of results) {
        if (result.success) {
          restoredCount++;
        } else {
          failedCount++;
          errors.push({ key: result.key, error: result.error });
        }
      }

      // 只写 KV 记录不够：恢复的文件还要写进索引、清掉随机图/公开列表缓存，
      // 否则在列表、随机图、公开浏览里都不出现，必须手动重建索引才可见。
      // 系统键与临时分块键不进索引。
      const indexFiles = restoredFiles.filter(file =>
        !file.fileId.startsWith('manage@') && !file.fileId.startsWith('chunk_'));
      if (indexFiles.length > 0) {
        const indexed = await batchAddFilesToIndex(context, indexFiles, { skipExisting: false });
        if (!indexed.success) {
          console.error('Failed to add restored files to index:', indexed.error);
        }
        // 清相关目录及祖先目录的随机/公开列表缓存（与打标签处同款做法）。
        const dirs = new Set(['']);
        for (const file of indexFiles) {
          const dir = file.fileId.split('/').slice(0, -1).join('/');
          dirs.add(dir);
          const segments = dir.split('/').filter(Boolean);
          while (segments.length > 1) { segments.pop(); dirs.add(segments.join('/')); }
        }
        const origin = new URL(request.url).origin;
        const invalidation = Promise.all([
          purgePublicFileListCache(origin, ...dirs),
          purgeRandomFileListCache(origin, ...dirs),
        ]);
        if (context.waitUntil) context.waitUntil(invalidation);
        else await invalidation;
      }
    } else if (type === 'settings') {
      // 恢复系统设置 - 并行写入
      // 备份时移除了 manage@ 前缀，恢复时需要加回来
      const settingPromises = Object.entries(data).map(async ([key, value]) => {
        try {
          // 设置值可能是对象或字符串
          const valueToStore = typeof value === 'string' ? value : JSON.stringify(value);
          // 加回 manage@ 前缀
          const fullKey = key.startsWith('manage@') ? key : `manage@${key}`;
          await db.put(fullKey, valueToStore);
          return { success: true };
        } catch (error) {
          return { success: false, key, error: error.message };
        }
      });

      const results = await Promise.all(settingPromises);
      for (const result of results) {
        if (result.success) {
          restoredCount++;
        } else {
          failedCount++;
          errors.push({ key: result.key, error: result.error });
        }
      }
    }

    return jsonResponse({
      success: true,
      restoredCount,
      failedCount,
      errors: errors.length > 0 ? errors.slice(0, 10) : undefined // 只返回前10个错误
    });

  } catch (error) {
    console.error('Error in BatchRestoreChunkAPI:', error);
    return errorResponse(`Server error: ${error.message}`, 500);
  }
}

/**
 * 处理 OPTIONS 请求 - CORS 预检
 */
export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: corsHeaders,
  });
}

/**
 * 默认请求处理器
 */
export async function onRequest(context) {
  const { request } = context;

  if (request.method === 'POST') {
    return onRequestPost(context);
  }

  if (request.method === 'OPTIONS') {
    return onRequestOptions();
  }

  return errorResponse('Method not allowed', 405);
}
