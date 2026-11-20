/**
 * HuggingFace 大文件提交 API
 * 
 * 在前端直接上传文件到 S3 后，调用此 API 提交 LFS 文件引用
 */

import { HuggingFaceAPI } from '../../utils/storage/huggingfaceAPI.js';
import { resolveFileType } from '../../utils/mimeTypes.js';
import { fetchPageConfig, fetchUploadConfig } from '../../utils/sysConfig.js';
import { getDatabase } from '../../utils/databaseAdapter.js';
import { moderateContent, endUpload, getUploadIp, getIPAddress, sanitizeUploadFolder, createResponse, checkUploadFormat } from '../uploadTools.js';
import { userAuthCheck, UnauthorizedResponse } from '../../utils/auth/userAuth.js';
import { resolveUploadExpiry } from '../../utils/fileExpiryService.js';

// 与 getUploadUrl.js 的 hfDirectIssuanceKey 保持一致（内联，避免跨模块导入）。
// commitUpload 只认 getUploadUrl 签发过的 fullId/filePath/渠道/哈希组合。
function hfDirectIssuanceKey(fullId) {
    return `hf_direct_upload_${fullId}`;
}

export async function onRequestPost(context) {
    const { request, env, waitUntil } = context;
    const url = new URL(request.url);

    try {
        // 鉴权
        const requiredPermission = 'upload';
        if (!await userAuthCheck(env, url, request, requiredPermission)) {
            return UnauthorizedResponse('Unauthorized');
        }

        const body = await request.json();
        const { fullId, filePath, sha256, fileSize, fileName, fileType, channelName } = body;

        if (!fullId || !filePath || !sha256 || !fileSize) {
            return createResponse(JSON.stringify({
                error: 'Missing required fields: fullId, filePath, sha256, fileSize'
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 路径安全处理：使用统一的路径安全函数
        const sanitizedFullId = sanitizeUploadFolder(fullId);
        if (sanitizedFullId !== fullId) {
            return createResponse(JSON.stringify({
                error: 'Invalid fullId: contains illegal path characters'
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 获取 HuggingFace 配置
        const uploadConfig = await fetchUploadConfig(env);
        const formatError = checkUploadFormat(fileName || fullId, uploadConfig);
        if (formatError) return formatError;
        const hfSettings = uploadConfig.huggingface;

        if (!hfSettings || !hfSettings.channels || hfSettings.channels.length === 0) {
            return createResponse(JSON.stringify({ error: 'No HuggingFace channel configured' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 选择渠道：只认 getUploadUrl 签发记录里的渠道。前端回传的 channelName
        // 必须与签发记录一致，否则拒绝；不回传时直接用签发记录的渠道，
        // 两步再也不会选到不同仓库（P1-43）。
        let hfChannel;
        if (channelName) {
            hfChannel = hfSettings.channels.find(c => c.name === channelName);
        }
        if (!hfChannel) {
            hfChannel = hfSettings.channels[0];
        }

        if (!hfChannel || !hfChannel.token || !hfChannel.repo) {
            return createResponse(JSON.stringify({ error: 'HuggingFace channel not properly configured' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 文件有效期由后端按设置决定（提交请求需携带与获取上传地址时相同的 expire 参数）；
        // 在提交远端文件之前校验，被拒绝的请求不会在 HuggingFace 留下没有记录的文件
        const expiry = await resolveUploadExpiry({ env, request, url });
        if (expiry.error) {
            return createResponse(JSON.stringify({ error: expiry.error }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // P1-43：fileSize 必须是正整数，sha256 必须是 64 位 hex
        if (!Number.isInteger(fileSize) || fileSize <= 0) {
            return createResponse(JSON.stringify({ error: 'fileSize must be a positive integer' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        if (typeof sha256 !== 'string' || !/^[0-9a-fA-F]{64}$/.test(sha256)) {
            return createResponse(JSON.stringify({ error: 'sha256 must be a 64-character hex string' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // P0-8：只接受 getUploadUrl 签发过的提交。签发记录不存在（没走
        // getUploadUrl、已过期、或 fullId 是现编的）直接拒绝；filePath 必须
        // 与签发的一致，客户端不能再拿任意 fullId/filePath 来覆盖已有文件。
        const db = getDatabase(env);
        const issuanceRaw = await db.get(hfDirectIssuanceKey(fullId));
        if (!issuanceRaw) {
            return createResponse(JSON.stringify({
                error: 'Missing or expired direct upload session; call getUploadUrl first'
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        let issuance;
        try {
            issuance = JSON.parse(issuanceRaw);
        } catch (e) {
            return createResponse(JSON.stringify({ error: 'Invalid direct upload session' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        if (issuance.filePath !== filePath || issuance.sha256 !== sha256 || issuance.fileSize !== fileSize) {
            return createResponse(JSON.stringify({ error: 'Direct upload session mismatch' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        if (channelName && issuance.channelName && channelName !== issuance.channelName) {
            return createResponse(JSON.stringify({ error: 'channelName does not match the direct upload session' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        const issuedChannel = hfSettings.channels.find(c => c.name === issuance.channelName);
        if (issuedChannel) {
            hfChannel = issuedChannel;
        }

        // db.put 前先 get：目标 fullId 已有记录时拒绝覆盖，防劫持 /file/<id>
        if ((await db.get(fullId)) !== null) {
            return createResponse(JSON.stringify({ error: 'File already exists' }), {
                status: 409,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const huggingfaceAPI = new HuggingFaceAPI(hfChannel.token, hfChannel.repo, hfChannel.isPrivate || false);

        // 提交 LFS 文件引用
        console.log('Committing LFS file...');
        const commitResult = await huggingfaceAPI.commitLfsFile(
            filePath,
            sha256,
            fileSize,
            `Upload ${fileName || fullId}`
        );
        console.log('Commit result:', JSON.stringify(commitResult));

        // 构建文件 URL
        const fileUrl = `https://huggingface.co/datasets/${hfChannel.repo}/resolve/main/${filePath}`;

        // 从 fullId 中提取目录信息
        const dirParts = fullId.split('/').slice(0, -1).join('/');
        const normalizedDirectory = dirParts === '' ? '' : dirParts + '/';

        // 获取上传IP和地址
        const uploadIp = getUploadIp(request) || '';
        const uploadAddress = await getIPAddress(env, uploadIp);

        // 构建 metadata
        const metadata = {
            FileName: fileName || fullId,
            FileType: resolveFileType(fileName || fullId, fileType),
            Channel: "HuggingFace",
            ChannelName: hfChannel.name || "HuggingFace_env",
            FileSize: (fileSize / 1024 / 1024).toFixed(2),
            FileSizeBytes: fileSize,
            UploadIP: uploadIp,
            UploadAddress: uploadAddress,
            ListType: "None",
            HfFilePath: filePath,
            TimeStamp: Date.now(),
            Label: "None",
            Directory: normalizedDirectory,
            Tags: []
        };

        if (expiry.expiresAt) {
            metadata.ExpiresAt = expiry.expiresAt;
        }

        // 图像审查（公开仓库）
        if (!hfChannel.isPrivate) {
            try {
                metadata.Label = await moderateContent(env, fileUrl);
            } catch (e) {
                console.warn('Content moderation failed:', e.message);
            }
        }

        // 写入数据库
        await db.put(fullId, "", { metadata });

        // 提交成功，签发记录作废（防重放第二次提交覆盖）
        await db.delete(hfDirectIssuanceKey(fullId)).catch(() => {});

        // 结束上传（更新索引等）
        const uploadContext = {
            env,
            waitUntil,
            uploadConfig,
            url,
            request
        };
        waitUntil(endUpload(uploadContext, fullId, metadata));

        // 返回成功响应
        const returnLink = `/file/${fullId}`;
        const responseBody = {
            success: true,
            src: returnLink,
            fileUrl,
            fullId
        };

        // 构建公开访问链接（使用 urlPrefix 配置）
        const pageConfig = await fetchPageConfig(env);
        const urlPrefixConfig = pageConfig.config?.find(c => c.id === 'urlPrefix');
        const urlPrefix = urlPrefixConfig?.value || '';
        if (urlPrefix) {
            responseBody.publicUrl = `${urlPrefix.replace(/\/+$/, '')}/${fullId}`;
        }
        if (metadata.ExpiresAt) {
            responseBody.expiresAt = metadata.ExpiresAt;
        }

        return createResponse(JSON.stringify(responseBody), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        console.error('commitUpload error:', error.message);
        return createResponse(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}
