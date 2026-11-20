import { readIndex } from "../../../utils/indexManager.js";
import { filterTagsByPrefix } from "../../../utils/tagHelpers.js";

// 单次联想最多扫描的文件数（索引按时间倒序，超出的旧文件标签不参与联想）。
const MAX_SCAN_FILES = 100000;

/**
 * Tag Autocomplete API
 *
 * GET /api/manage/tags/autocomplete?prefix=ph - Get tag suggestions
 *
 * Returns all tags matching the given prefix, useful for autocomplete functionality
 */
export async function onRequest(context) {
    const { request } = context;

    const url = new URL(request.url);

    if (request.method !== 'GET') {
        return new Response(JSON.stringify({
            error: 'Method not allowed',
            allowedMethods: ['GET']
        }), {
            status: 405,
            headers: { 'Content-Type': 'application/json' }
        });
    }

    try {
        // Get prefix from query parameters
        const prefix = url.searchParams.get('prefix') || '';
        const limit = parseInt(url.searchParams.get('limit') || '20', 10);

        // Validate limit
        if (limit < 1 || limit > 100) {
            return new Response(JSON.stringify({
                error: 'Invalid limit',
                message: 'Limit must be between 1 and 100'
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 全量扫描索引去重：只看前 1000 个文件时，图库大了以后一些标签搜不出来。
        // readIndex 本来就会把整份索引读进内存一次，因此一次取全量比分多页反复读更省；
        // 为防超大图库失控，只扫前 MAX_SCAN_FILES 条（按时间倒序，即最新的优先），
        // 超出时在响应里标明 truncated。
        const result = await readIndex(context, {
            start: 0,
            count: -1,
            includeSubdirFiles: true
        });

        if (!result.success) {
            return new Response(JSON.stringify({
                error: 'Failed to read index',
                message: 'Index not available'
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Extract unique tags from files
        const allTags = new Set();
        const scannedFiles = result.files.slice(0, MAX_SCAN_FILES);
        for (const file of scannedFiles) {
            if (file.metadata && Array.isArray(file.metadata.Tags)) {
                file.metadata.Tags.forEach(tag => {
                    if (tag && typeof tag === 'string') {
                        allTags.add(tag.toLowerCase().trim());
                    }
                });
            }
        }

        // Convert to array and sort
        const tagsArray = Array.from(allTags).sort();

        // Filter by prefix
        const filteredTags = prefix
            ? filterTagsByPrefix(tagsArray, prefix, limit)
            : tagsArray.slice(0, limit);

        return new Response(JSON.stringify({
            success: true,
            prefix: prefix,
            tags: filteredTags,
            total: filteredTags.length,
            hasMore: tagsArray.length > filteredTags.length,
            scannedFiles: scannedFiles.length,
            truncated: result.files.length > MAX_SCAN_FILES
        }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Cache-Control': 'private, max-age=60'
            }
        });

    } catch (error) {
        console.error('Error in tag autocomplete:', error);
        return new Response(JSON.stringify({
            error: 'Internal server error',
            message: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}
