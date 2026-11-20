import {
    readIndex, mergeOperationsToIndex, deleteAllOperations, rebuildIndex,
    getIndexInfo, getIndexStorageStats
} from '../../utils/indexManager.js';
import { getDatabase } from '../../utils/databaseAdapter.js';
import { authenticate, AUTH_SCOPE } from '../../utils/auth/authCore.js';
import { createMetadataViewContext, serializeFileRecordForManagement } from '../../utils/metadata/metadataView.js';
import { maybeCleanupExpiredFiles } from '../../utils/fileExpiryService.js';

// CORS 跨域响应头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
};

export async function onRequest(context) {
    const { request, waitUntil } = context;
    const url = new URL(request.url);

    // 管理端打开文件列表时顺带清理一批到期文件（Pages 没有定时任务，依靠它和手动清理）
    maybeCleanupExpiredFiles(context);

    // 解析查询参数
    let start = parseInt(url.searchParams.get('start'), 10) || 0;
    let count = parseInt(url.searchParams.get('count'), 10) || 50;
    let sum = url.searchParams.get('sum') === 'true';
    let recursive = url.searchParams.get('recursive') === 'true';
    let dir = url.searchParams.get('dir') || '';
    let search = url.searchParams.get('search') || '';
    let channel = url.searchParams.get('channel') || '';
    let listType = url.searchParams.get('listType') || '';
    let accessStatus = url.searchParams.get('accessStatus') || '';
    let action = url.searchParams.get('action') || '';
    let includeTags = url.searchParams.get('includeTags') || '';
    let excludeTags = url.searchParams.get('excludeTags') || '';
    let label = url.searchParams.get('label') || '';
    let fileType = url.searchParams.get('fileType') || '';
    let channelName = url.searchParams.get('channelName') || '';

    // 处理搜索关键字
    if (search) {
        search = decodeURIComponent(search).trim();
    }

    // 处理标签参数
    const includeTagsArray = includeTags ? includeTags.split(',').map(t => t.trim()).filter(t => t) : [];
    const excludeTagsArray = excludeTags ? excludeTags.split(',').map(t => t.trim()).filter(t => t) : [];

    // 处理筛选参数（支持逗号分隔的多选）
    const listTypeArray = listType ? listType.split(',').map(t => t.trim()).filter(t => t) : [];
    const accessStatusArray = accessStatus ? accessStatus.split(',').map(t => t.trim()).filter(t => t) : [];
    const labelArray = label ? label.split(',').map(t => t.trim()).filter(t => t) : [];
    const fileTypeArray = fileType ? fileType.split(',').map(t => t.trim()).filter(t => t) : [];
    const channelArray = channel ? channel.split(',').map(t => t.trim()).filter(t => t) : [];
    const channelNameArray = channelName ? channelName.split(',').map(t => t.trim()).filter(t => t) : [];

    // 处理目录参数
    if (dir) {
        // 路径安全处理：防止路径穿越
        dir = dir.replace(/\.\./g, '_').replace(/\\/g, '/').replace(/\/{2,}/g, '/');
    }
    if (dir.startsWith('/')) {
        dir = dir.substring(1);
    }
    if (dir && !dir.endsWith('/')) {
        dir += '/';
    }

    try {
        // 重建索引、合并操作、清空操作队列会改写索引或丢弃未合并的操作，
        // 中间件对 /api/manage/list 只要求 list 权限，仅 list 权限的 Token 也能调到这里，
        // 因此这三个动作再核一次 manage 权限；其余 list 动作保持 list 权限。
        // 这三个动作同时是 GET 可触发的状态变更，做同站检查防 CSRF
        // （见 delete/[[path]].js 的说明；服务端内调会转发原请求头，通过检查）。
        if (action === 'rebuild' || action === 'merge-operations' || action === 'delete-operations') {
            const forbidden = rejectCrossSiteRequest(request);
            if (forbidden) return forbidden;
            const manageAuth = await authenticate({
                env: context.env,
                request,
                requiredPermission: 'manage',
                authScope: AUTH_SCOPE.ADMIN,
            });
            if (!manageAuth.authorized) {
                return new Response('You need to login', {
                    status: 401,
                    headers: { 'Content-Type': 'text/plain;charset=UTF-8', ...corsHeaders },
                });
            }
        }

        // 特殊操作：重建索引
        if (action === 'rebuild') {
            waitUntil(rebuildIndex(context, (processed) => {
                console.log(`Rebuilt ${processed} files...`);
            }));

            return new Response('Index rebuilt asynchronously', {
                headers: { "Content-Type": "text/plain", ...corsHeaders }
            });
        }

        // 特殊操作：合并挂起的原子操作到索引
        if (action === 'merge-operations') {
            waitUntil(mergeOperationsToIndex(context));

            return new Response('Operations merged into index asynchronously', {
                headers: { "Content-Type": "text/plain", ...corsHeaders }
            });
        }

        // 特殊操作：清除所有原子操作
        if (action === 'delete-operations') {
            waitUntil(deleteAllOperations(context));

            return new Response('All operations deleted asynchronously', {
                headers: { "Content-Type": "text/plain", ...corsHeaders }
            });
        }

        // 特殊操作：获取索引存储信息
        if (action === 'index-storage-stats') {
            const stats = await getIndexStorageStats(context);
            return new Response(JSON.stringify(stats), {
                headers: { "Content-Type": "application/json", ...corsHeaders }
            });
        }

        // 特殊操作：获取索引信息
        if (action === 'info') {
            const info = await getIndexInfo(context, {
                timezoneOffset: url.searchParams.get('timezoneOffset'),
                maxPoints: url.searchParams.get('trendMaxPoints'),
                seriesLimit: url.searchParams.get('trendSeriesLimit'),
                startDate: url.searchParams.get('trendStartDate'),
                endDate: url.searchParams.get('trendEndDate')
            });
            return new Response(JSON.stringify(info), {
                headers: { "Content-Type": "application/json", ...corsHeaders }
            });
        }

        // 普通查询：只返回总数
        if (count === -1 && sum) {
            const result = await readIndex(context, {
                search,
                directory: dir,
                channel: channelArray,
                listType: listTypeArray,
                accessStatus: accessStatusArray,
                label: labelArray,
                fileType: fileTypeArray,
                channelName: channelNameArray,
                includeTags: includeTagsArray,
                excludeTags: excludeTagsArray,
                countOnly: true
            });

            return new Response(JSON.stringify({
                sum: result.totalCount,
                indexLastUpdated: result.indexLastUpdated
            }), {
                headers: { "Content-Type": "application/json", ...corsHeaders }
            });
        }

        // 普通查询：返回数据
        const result = await readIndex(context, {
            search,
            directory: dir,
            start,
            count,
            channel: channelArray,
            listType: listTypeArray,
            accessStatus: accessStatusArray,
            label: labelArray,
            fileType: fileTypeArray,
            channelName: channelNameArray,
            includeTags: includeTagsArray,
            excludeTags: excludeTagsArray,
            includeSubdirFiles: recursive,
        });

        // 索引读取失败，直接从 KV 中获取所有文件记录；
        // 兜底分支同样应用搜索、筛选与分页，不再静默返回未过滤的全部数据。
        if (!result.success) {
            const dbRecords = await getAllFileRecords(context.env, dir, {
                search,
                channel: channelArray,
                listType: listTypeArray,
                accessStatus: accessStatusArray,
                label: labelArray,
                fileType: fileTypeArray,
                channelName: channelNameArray,
                includeTags: includeTagsArray,
                excludeTags: excludeTagsArray,
                start,
                count,
                includeSubdirFiles: recursive,
            });

            return new Response(JSON.stringify({
                files: dbRecords.files,
                directories: dbRecords.directories,
                totalCount: dbRecords.totalCount,
                directFileCount: dbRecords.directFileCount,
                directFolderCount: dbRecords.directFolderCount,
                returnedCount: dbRecords.returnedCount,
                indexLastUpdated: Date.now(),
                isIndexedResponse: false // 标记这是来自 KV 的响应
            }), {
                headers: { "Content-Type": "application/json", ...corsHeaders }
            });
        }

        const db = getDatabase(context.env);
        const metadataViewContext = await createMetadataViewContext(db, context.env);

        // 转换文件格式
        const compatibleFiles = await Promise.all(
            result.files.map(file => serializeFileRecordForManagement(db, context.env, file, metadataViewContext))
        );

        return new Response(JSON.stringify({
            files: compatibleFiles,
            directories: result.directories,
            totalCount: result.totalCount,
            directFileCount: result.directFileCount,
            directFolderCount: result.directFolderCount,
            returnedCount: result.returnedCount,
            indexLastUpdated: result.indexLastUpdated,
            isIndexedResponse: true // 标记这是来自索引的响应
        }), {
            headers: { "Content-Type": "application/json", ...corsHeaders }
        });

    } catch (error) {
        console.error('Error in list-indexed API:', error);
        return new Response(JSON.stringify({
            error: 'Internal server error',
            message: error.message
        }), {
            status: 500,
            headers: { "Content-Type": "application/json", ...corsHeaders }
        });
    }
}

async function getAllFileRecords(env, dir, filters = {}) {
    const {
        search = '',
        channel = [],
        listType = [],
        accessStatus = [],
        label = [],
        fileType = [],
        channelName = [],
        includeTags = [],
        excludeTags = [],
        start = 0,
        count = 50,
        includeSubdirFiles = false,
    } = filters;
    const allRecords = [];
    let cursor = null;

    try {
        const db = getDatabase(env);
        const metadataViewContext = await createMetadataViewContext(db, env);

        while (true) {
            const response = await db.list({
                prefix: dir,
                limit: 1000,
                cursor: cursor
            });

            // 检查响应格式
            if (!response || !response.keys || !Array.isArray(response.keys)) {
                console.error('Invalid response from database list:', response);
                break;
            }

            cursor = response.cursor;

            for (const item of response.keys) {
                // 跳过管理相关的键
                if (item.name.startsWith('manage@') || item.name.startsWith('chunk_')) {
                    continue;
                }

                // 跳过没有元数据的文件
                if (!item.metadata || !item.metadata.TimeStamp) {
                    continue;
                }

                allRecords.push(await serializeFileRecordForManagement(db, env, item, metadataViewContext));
            }

            if (!cursor) break;

            // 添加协作点
            await new Promise(resolve => setTimeout(resolve, 10));
        }

        // 与 readIndex 同一套筛选语义（搜索、渠道、黑白名单、访问状态、审查结果、
        // 文件类型、渠道名称、标签），避免兜底分支静默返回未过滤数据。
        const filteredRecords = allRecords.filter(item => matchesListFilters(item, {
            search, channel, listType, accessStatus, label, fileType, channelName, includeTags, excludeTags,
        }));

        // 提取目录信息
        const directories = new Set();
        const directFiles = [];
        filteredRecords.forEach(item => {
            const subDir = item.name.substring(dir.length);
            const firstSlashIndex = subDir.indexOf('/');
            if (firstSlashIndex !== -1) {
                directories.add(dir + subDir.substring(0, firstSlashIndex));
            } else {
                directFiles.push(item);
            }
        });

        // 非递归时只返回直接文件，总数也只计直接文件，与索引分支一致。
        const visibleFiles = includeSubdirFiles ? filteredRecords : directFiles;
        const totalCount = visibleFiles.length;
        const pagedFiles = count === -1
            ? visibleFiles.slice(Math.max(0, start))
            : visibleFiles.slice(Math.max(0, start), Math.max(0, start) + Math.max(1, count));

        return {
            files: pagedFiles,
            directories: Array.from(directories),
            totalCount,
            directFileCount: directFiles.length,
            directFolderCount: directories.size,
            returnedCount: pagedFiles.length
        };

    } catch (error) {
        console.error('Error in getAllFileRecords:', error);
        return {
            files: [],
            directories: [],
            totalCount: 0,
            directFileCount: 0,
            directFolderCount: 0,
            returnedCount: 0,
            error: error.message
        };
    }
}

// 与 readIndex 相同的列表筛选谓词（供索引不可用的 KV 兜底分支复用）。
function matchesListFilters(item, filters) {
    const metadata = item.metadata || {};
    const {
        search = '', channel = [], listType = [], accessStatus = [],
        label = [], fileType = [], channelName = [],
        includeTags = [], excludeTags = [],
    } = filters;

    if (channel.length > 0 && !channel.some(ch => metadata.Channel?.toLowerCase() === ch.toLowerCase())) {
        return false;
    }

    if (listType.length > 0) {
        const fileListType = metadata.ListType;
        if (!listType.some(lt => lt === 'None'
            ? !fileListType || fileListType === '' || fileListType === 'None'
            : fileListType === lt)) return false;
    }

    if (accessStatus.length > 0) {
        const isBlocked = metadata.ListType === 'Block' || (metadata.Label === 'adult' && metadata.ListType !== 'White');
        if (!accessStatus.some(status => status === 'normal' ? !isBlocked : status === 'blocked' ? isBlocked : false)) return false;
    }

    if (label.length > 0) {
        const fileLabel = metadata.Label;
        if (!label.some(lbl => lbl === 'normal'
            ? !fileLabel || fileLabel === '' || fileLabel === 'None' || fileLabel === 'everyone'
            : lbl === 'teen' ? fileLabel === 'teen'
            : lbl === 'adult' ? fileLabel === 'adult' : false)) return false;
    }

    if (fileType.length > 0) {
        const type = (metadata.FileType || '').toLowerCase();
        const category = type.startsWith('image/') ? 'image'
            : type.startsWith('video/') ? 'video'
            : type.startsWith('audio/') ? 'audio' : 'other';
        if (!fileType.includes(category)) return false;
    }

    if (channelName.length > 0) {
        const fileChannel = metadata.Channel;
        const fileChannelName = metadata.ChannelName;
        if (!channelName.some(filterValue => {
            if (filterValue.includes(':')) {
                const [type, name] = filterValue.split(':', 2);
                return fileChannel === type && fileChannelName === name;
            }
            return fileChannelName === filterValue;
        })) return false;
    }

    if (includeTags.length > 0 || excludeTags.length > 0) {
        const fileTags = (metadata.Tags || []).map(t => t.toLowerCase());
        if (includeTags.length > 0 && !includeTags.every(tag => fileTags.includes(tag.toLowerCase()))) return false;
        if (excludeTags.length > 0 && excludeTags.some(tag => fileTags.includes(tag.toLowerCase()))) return false;
    }

    if (search) {
        const searchLower = search.toLowerCase();
        if (!metadata.FileName?.toLowerCase().includes(searchLower) && !item.name.toLowerCase().includes(searchLower)) {
            return false;
        }
    }

    return true;
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
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
}
