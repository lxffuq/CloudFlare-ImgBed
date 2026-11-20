import { createS3Client } from '../../../utils/storage/s3Client.js';
import { CopyObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { purgeCFCache, purgeRandomFileListCache, purgePublicFileListCache } from "../../../utils/purgeCache";
import { moveFileInIndex, batchMoveFilesInIndex } from "../../../utils/indexManager.js";
import { getDatabase } from '../../../utils/databaseAdapter.js';
import { sanitizeUploadFolder } from "../../../upload/uploadTools.js";
import { WebDAVAPI } from "../../../utils/storage/webdavAPI.js";
import {
    resolveS3Credentials,
    resolveWebDAVCredentials,
} from "../../../utils/metadata/channelCredentials.js";
import { cleanPersistedMetadata } from "../../../utils/metadata/metadataSecurity.js";

export async function onRequest(context) {
    const { request, env, params, waitUntil } = context;

    // 前端是预编译 bundle，仍用 GET 调移动接口，因此不禁 GET，改为同站检查
    // （见 delete/[[path]].js 的说明）：跨站信号拒绝，无信号放行。
    const forbidden = rejectCrossSiteRequest(request);
    if (forbidden) return forbidden;

    const url = new URL(request.url);

    // 读取目标文件夹，并进行路径安全处理
    const rawDist = url.searchParams.get('dist') || '';
    const dist = sanitizeUploadFolder(rawDist);

    // 读取folder参数，判断是否为文件夹移动请求
    const folder = url.searchParams.get('folder');
    if (folder === 'true') {
        try {
            params.path = decodeURIComponent(params.path);
            const sourceFolder = params.path.split(',').join('/');
            const sourceName = sourceFolder.split('/').pop();
            // 移动后的文件夹根路径：dist 为空时留在原地同名，否则为 dist/原名。
            const targetFolder = dist === '' ? sourceName : `${dist}/${sourceName}`;
            // 移到自身或子目录下会无限嵌套：先挡住，什么都不写。
            if (targetFolder === sourceFolder || targetFolder.startsWith(sourceFolder + '/')) {
                return new Response(JSON.stringify({
                    success: false,
                    error: 'Cannot move a folder into itself or its subdirectory'
                }), { status: 400 });
            }

            // 第一阶段：只收集，不写任何记录——先把整棵树要搬的文件一次枚举完。
            const folderQueue = [{
                path: sourceFolder,
                dist: dist
            }];
            const plannedMoves = [];

            while (folderQueue.length > 0) {
                const currentFolder = folderQueue.shift();
                const curFolderName = currentFolder.path.split('/').pop();

                // 获取指定目录下的所有文件
                const listUrl = new URL(`${url.origin}/api/manage/list?count=-1&dir=${currentFolder.path}`);
                const listRequest = new Request(listUrl, {
                    headers: request.headers,
                });
                const listResponse = await fetch(listRequest);
                const listData = await listResponse.json();

                const files = listData.files;
                const folderDist = currentFolder.dist === '' ? curFolderName : `${currentFolder.dist}/${curFolderName}`;

                // 处理当前文件夹下的所有文件
                for (const file of files) {
                    const fileId = file.name;
                    const fileName = file.name.split('/').pop();
                    const newFileId = `${folderDist}/${fileName}`;
                    plannedMoves.push({ fileId, newFileId });
                }

                // 将子文件夹添加到队列
                const directories = listData.directories;
                for (const dir of directories) {
                    folderQueue.push({
                        path: dir,
                        dist: folderDist
                    });
                }
            }

            // 第二阶段：全量预检——任一目标已存在就直接 400，之前不写任何记录。
            const db = getDatabase(env);
            for (const { fileId, newFileId } of plannedMoves) {
                if (newFileId === fileId) continue; // 原地移动是幂等空操作，不算冲突
                const existing = await db.getWithMetadata(newFileId);
                if (existing && existing.value !== null && existing.value !== undefined) {
                    return new Response(JSON.stringify({
                        success: false,
                        error: `Target already exists: ${newFileId}`
                    }), { status: 409 });
                }
            }

            // 第三阶段：执行搬移
            const processedFiles = [];
            const failedFiles = [];

            for (const { fileId, newFileId } of plannedMoves) {
                const cdnUrl = `https://${url.hostname}/file/${fileId}`;
                const result = await moveFile(env, fileId, newFileId, cdnUrl, url);
                if (result.ok) {
                    processedFiles.push({ fileId: fileId, newFileId: newFileId });
                } else {
                    failedFiles.push(fileId);
                }
            }

            // 批量从索引中删除文件，添加新文件
            if (processedFiles.length > 0) {
                waitUntil(batchMoveFilesInIndex(context, processedFiles.map(file => {
                    return {
                        originalFileId: file.fileId,
                        newFileId: file.newFileId,
                    };
                })));
            }

            // 返回处理结果
            return new Response(JSON.stringify({
                success: failedFiles.length === 0,
                processed: processedFiles,
                failed: failedFiles
            }));

        } catch (e) {
            return new Response(JSON.stringify({
                success: false,
                error: e.message
            }), { status: 400 });
        }
    }

    // 单个文件移动处理
    try {
        // 解码params.path
        params.path = decodeURIComponent(params.path);
        const fileId = params.path.split(',').join('/');
        const fileKey = fileId.split('/').pop();
        const newFileId = dist === '' ? fileKey : `${dist}/${fileKey}`;
        const cdnUrl = `https://${url.hostname}/file/${fileId}`;

        const result = await moveFile(env, fileId, newFileId, cdnUrl, url);
        if (!result.ok) {
            if (result.status === 409) {
                return new Response(JSON.stringify({
                    success: false,
                    error: result.message
                }), { status: 409 });
            }
            throw new Error(result.message || 'Move file failed');
        } else {
            // 从索引中删除旧文件，并添加新文件（原地移动是空操作，不写索引）
            if (!result.noop) waitUntil(moveFileInIndex(context, fileId, newFileId));
        }

        return new Response(JSON.stringify({
            success: true,
            fileId: fileId,
            newFileId: newFileId
        }));
    } catch (e) {
        return new Response(JSON.stringify({
            success: false,
            error: e.message
        }), { status: 400 });
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
    return new Response(JSON.stringify({ success: false, error: 'Cross-site request forbidden' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
    });
}

// 移动单个文件的核心函数
// 返回 { ok: true, noop?: boolean } 或 { ok: false, status?: number, message?: string }。
async function moveFile(env, fileId, newFileId, cdnUrl, url) {
    try {
        // 移到自己所在位置是幂等空操作，直接返回成功，不碰存储。
        if (newFileId === fileId) {
            return { ok: true, noop: true };
        }

        const db = getDatabase(env);

        // 读取图片信息
        const img = await db.getWithMetadata(fileId);

        // 目标已存在时拒绝：R2/S3 路径先 put 再 delete，同名会先覆盖再删掉目标。
        const existing = await db.getWithMetadata(newFileId);
        if (existing && existing.value !== null && existing.value !== undefined) {
            return { ok: false, status: 409, message: `Target already exists: ${newFileId}` };
        }

        // 如果是R2渠道的图片，需要移动R2中对应的图片
        if (img.metadata?.Channel === 'CloudflareR2') {
            const R2DataBase = env.img_r2;

            // 获取原文件内容
            const object = await R2DataBase.get(fileId);
            if (!object) {
                throw new Error('R2 Object Not Found');
            }

            // 复制到新位置
            await R2DataBase.put(newFileId, object.body);

            // 删除旧文件
            await R2DataBase.delete(fileId);
        }

        // S3 渠道的图片，需要移动S3中对应的图片
        if (img.metadata?.Channel === 'S3') {
            const { success, newKey, error } = await moveS3File(env, img, newFileId);
            if (!success) {
                throw new Error(error || 'S3 Move Failed');
            }
            img.metadata.S3FileKey = newKey;
        }

        // WebDAV 渠道的图片，需要移动 WebDAV 中对应的文件
        if (img.metadata?.Channel === 'WebDAV') {
            const { success, error } = await moveWebDAVFile(env, img, newFileId);
            if (!success) {
                throw new Error(error || 'WebDAV Move Failed');
            }
            img.metadata.WebDAVFilePath = newFileId;
        }

        // 旧版 Telegram 渠道和 Telegraph 渠道不支持移动
        if (img.metadata?.Channel === 'Telegram' || img.metadata?.Channel === undefined) {
            throw new Error('Unsupported Channel');
        }

        // 更新文件夹信息，根目录为空，否则为 aaa/123/ 的格式
        const DirectoryPath = newFileId.split('/').slice(0, -1).join('/') === '' ? '' : newFileId.split('/').slice(0, -1).join('/') + '/';
        img.metadata.Directory = DirectoryPath;
        img.metadata = cleanPersistedMetadata(img.metadata);

        // 更新KV存储
        await db.put(newFileId, img.value, { metadata: img.metadata });
        await db.delete(fileId);

        // 清除CDN缓存
        await purgeCFCache(env, cdnUrl);

        // 清除 api/randomFileList 等API缓存
        const normalizedFolder = fileId.split('/').slice(0, -1).join('/');
        const normalizedDist = newFileId.split('/').slice(0, -1).join('/');
        await purgeRandomFileListCache(url.origin, normalizedFolder, normalizedDist);
        await purgePublicFileListCache(url.origin, normalizedFolder, normalizedDist);

        return { ok: true };
    } catch (e) {
        console.error('Move file failed:', e);
        return { ok: false, message: e.message };
    }
}

// 移动 S3 渠道的图片
async function moveS3File(env, img, newFileId) {
    const db = getDatabase(env);
    const s3Credentials = await resolveS3Credentials(db, env, img.metadata);
    const s3Client = createS3Client(s3Credentials);

    const bucketName = s3Credentials.bucketName;
    const oldKey = s3Credentials.key;
    const newKey = newFileId;

    try {
        // 复制文件到新位置
        await s3Client.send(new CopyObjectCommand({
            Bucket: bucketName,
            CopySource: `/${bucketName}/${oldKey}`,
            Key: newKey,
        }));

        // 复制成功后，删除旧文件
        await s3Client.send(new DeleteObjectCommand({
            Bucket: bucketName,
            Key: oldKey,
        }));

        // 返回新的 S3 文件信息
        return {
            success: true,
            newKey,
            endpoint: s3Credentials.endpoint,
            bucketName,
            source: s3Credentials.source
        };
    } catch (error) {
        console.error("S3 Move Failed:", error);
        return { success: false, error: error.message };
    }
}

// 移动 WebDAV 渠道的图片
async function moveWebDAVFile(env, img, newFileId) {
    const oldPath = img.metadata?.WebDAVFilePath;

    if (!oldPath) {
        return { success: false, error: 'WebDAV file missing required metadata for move' };
    }

    try {
        const db = getDatabase(env);
        const webdavConfig = await resolveWebDAVCredentials(db, env, img.metadata);
        if (!webdavConfig.baseUrl) {
            return { success: false, error: 'WebDAV channel config not found for move' };
        }

        const webdavAPI = new WebDAVAPI(webdavConfig);
        await webdavAPI.moveFile(oldPath, newFileId, true);
        return { success: true, newKey: newFileId, webdavConfig };
    } catch (error) {
        console.error("WebDAV Move Failed:", error);
        return { success: false, error: error.message };
    }
}
