import { authenticate, AUTH_SCOPE } from "../../utils/auth/authCore.js";

const DEFAULT_MANAGE_CACHE_CONTROL = 'private, no-store, max-age=0';

function withDefaultCacheControl(response) {
  if (response.headers.has('Cache-Control')) {
    return response;
  }

  const headers = new Headers(response.headers);
  headers.set('Cache-Control', DEFAULT_MANAGE_CACHE_CONTROL);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function errorHandling(context) {
  try {
    return withDefaultCacheControl(await context.next());
  } catch (err) {
    // 只把堆栈写服务端日志，不回显给客户端
    console.error('Manage API error:', err && err.stack ? err.stack : err);
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': DEFAULT_MANAGE_CACHE_CONTROL,
      },
    });
  }
}

function UnauthorizedException(reason) {
  return new Response(reason, {
    status: 401,
    statusText: 'Unauthorized',
    headers: {
      'Content-Type': 'text/plain;charset=UTF-8',
      'Cache-Control': 'no-store',
      'Content-Length': reason.length,
    },
  });
}

/**
 * 根据请求路径提取所需权限
 * @param {string} pathname - 请求路径
 * @returns {string} 需要的权限类型
 */
function extractRequiredPermission(pathname) {
  const path = pathname.toLowerCase().replace(/\/$/, '');
  if (path === '/api/manage/delete' || path.startsWith('/api/manage/delete/')) {
    return 'delete';
  }
  if (path === '/api/manage/list' || path.startsWith('/api/manage/list/') || path === '/api/manage/batch/list') {
    return 'list';
  }

  // 其他 /api/manage 下的操作需要管理权限
  return 'manage';
}

// CORS 跨域响应头
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, PUT, PATCH, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

async function authentication(context) {
  // OPTIONS 预检请求不需要鉴权，直接返回 CORS 响应
  if (context.request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: corsHeaders
    });
  }

  const pathname = new URL(context.request.url).pathname;
  const requiredPermission = extractRequiredPermission(pathname);

  const result = await authenticate({
    env: context.env,
    request: context.request,
    requiredPermission,
    authScope: AUTH_SCOPE.ADMIN,
  });

  // 安全配置读失败：fail-closed，返回 503 而不是 401（避免被当成“未登录”重试登录）
  if (result.configError) {
    return new Response(JSON.stringify({ error: 'Security config unavailable' }), {
      status: 503,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
      },
    });
  }

  if (!result.authorized) {
    return UnauthorizedException('You need to login');
  }

  return context.next();
}

export const onRequest = [errorHandling, authentication];
