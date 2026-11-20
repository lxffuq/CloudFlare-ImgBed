/**
 * HuggingFace 大文件直传 API
 *
 * 流程：
 * 1. 前端计算 SHA256 和文件样本
 * 2. 前端调用此 API 获取 LFS 上传 URL
 * 3. 前端直接上传到 HuggingFace S3
 * 4. 前端调用 commitUpload API 提交文件引用
 *
 * 这样可以绕过 CF Workers 的 100MB 请求体限制和 CPU 时间限制
 */

import { HuggingFaceAPI } from '../../utils/storage/huggingfaceAPI.js';
import { resolveFileType } from '../../utils/mimeTypes.js';
import { fetchUploadConfig } from '../../utils/sysConfig.js';
import { getDatabase } from '../../utils/databaseAdapter.js';
import { userAuthCheck, UnauthorizedResponse } from '../../utils/auth/userAuth.js';
import { buildUniqueFileId, getUploadIp, isBlockedUploadIp, createResponse, checkUploadFormat, selectConsistentChannel, isValidSha256, isPositiveInteger } from '../uploadTools.js';
import { resolveUploadExpiry } from '../../utils/fileExpiryService.js';

// P0-8：getUploadUrl 签发的直传会话记录键。commitUpload 只认这里签发过的
// fullId/filePath/渠道/哈希，签发记录 TTL 24 小时（大文件直传可能耗时很久）。
export const HF_DIRECT_ISSUANCE_TTL_SECONDS = 86400;

export function hfDirectIssuanceKey(fullId) {
    return `hf_direct_upload_${fullId}`;
}

export async function onRequestPost(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    context.url = url;  // 将 url 添加到 context 以便 buildUniqueFileId 使用

    try {
        // 鉴权
        const requiredPermission = 'upload';
        if (!await userAuthCheck(env, url, request, requiredPermission)) {
            return UnauthorizedResponse('Unauthorized');
        }

        // 检查上传IP是否被封禁
        const uploadIp = getUploadIp(request);
        if (await isBlockedUploadIp(env, uploadIp)) {
            return createResponse(JSON.stringify({ error: 'IP blocked' }), {
                status: 403,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const body = await request.json();
        const { fileSize, fileName, fileType, sha256, fileSample, channelName, uploadNameType, uploadFolder } = body;
        const normalizedFileType = resolveFileType(fileName, fileType);

        if (!fileSize || !fileName || !sha256 || !fileSample) {
            return createResponse(JSON.stringify({
                error: 'Missing required fields: fileSize, fileName, sha256, fileSample'
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 直传前校验有效期参数，避免文件已传到 HuggingFace 才在提交时被拒绝
        const expiry = await resolveUploadExpiry(context);
        if (expiry.error) {
            return createResponse(JSON.stringify({ error: expiry.error }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 获取 HuggingFace 配置
        const uploadConfig = await fetchUploadConfig(env);
        const formatError = checkUploadFormat(fileName, uploadConfig);
        if (formatError) return formatError;

        // P1-43：fileSize 必须是正整数，sha256 必须是 64 位 hex
        if (!isPositiveInteger(fileSize)) {
            return createResponse(JSON.stringify({ error: 'fileSize must be a positive integer' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        if (!isValidSha256(sha256)) {
            return createResponse(JSON.stringify({ error: 'sha256 must be a 64-character hex string' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        const hfSettings = uploadConfig.huggingface;

        if (!hfSettings || !hfSettings.channels || hfSettings.channels.length === 0) {
            return createResponse(JSON.stringify({ error: 'No HuggingFace channel configured' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 选择渠道
        let hfChannel;
        if (channelName) {
            hfChannel = hfSettings.channels.find(c => c.name === channelName);
            if (!hfChannel) {
                return createResponse(JSON.stringify({ error: 'HuggingFace channel not found' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        }
        if (!hfChannel) {
            // 不再随机选渠道：按文件哈希确定性选渠道；commitUpload 只认
            // 下面写入的签发记录里的渠道，两步不可能再选到不同仓库（P1-43）。
            hfChannel = selectConsistentChannel(hfSettings.channels, `${fileName}:${sha256}`, hfSettings.loadBalance?.enabled);
        }

        if (!hfChannel || !hfChannel.token || !hfChannel.repo) {
            return createResponse(JSON.stringify({ error: 'HuggingFace channel not properly configured' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // 将命名参数添加到 URL 以便 buildUniqueFileId 使用
        if (uploadNameType) {
            url.searchParams.set('uploadNameType', uploadNameType);
        }
        if (uploadFolder) {
            url.searchParams.set('uploadFolder', uploadFolder);
        }

        // 使用统一的文件命名函数生成文件ID
        const fullId = await buildUniqueFileId(context, fileName, normalizedFileType);

        // 生成唯一标识符前缀（UUID格式），加在文件名前面
        const uniquePrefix = crypto.randomUUID();
        const lastSlashIndex = fullId.lastIndexOf('/');
        const filePath = lastSlashIndex === -1 
            ? `${uniquePrefix}_${fullId}` 
            : `${fullId.substring(0, lastSlashIndex + 1)}${uniquePrefix}_${fullId.substring(lastSlashIndex + 1)}`;

        // P0-8：把这次签发的 fullId/filePath/渠道/哈希写进服务端记录，
        // commitUpload 只认签发过的组合，客户端再也无法拿任意 fullId 来覆盖已有文件。
        const db = getDatabase(env);
        await db.put(hfDirectIssuanceKey(fullId), JSON.stringify({
            fullId,
            filePath,
            channelName: hfChannel.name,
            sha256,
            fileSize,
            uploadIp,
            createdAt: Date.now(),
        }), { expirationTtl: HF_DIRECT_ISSUANCE_TTL_SECONDS });

        // 获取 LFS 上传信息
        const huggingfaceAPI = new HuggingFaceAPI(hfChannel.token, hfChannel.repo, hfChannel.isPrivate || false);
        const uploadInfo = await huggingfaceAPI.getLfsUploadInfo(fileSize, filePath, sha256, fileSample);
        rewriteMultipartCompletionUrl(url, uploadInfo);

        // 返回上传信息
        return createResponse(JSON.stringify({
            success: true,
            fullId,
            filePath,
            channelName: hfChannel.name,
            repo: hfChannel.repo,
            isPrivate: hfChannel.isPrivate || false,
            ...uploadInfo
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        console.error('getUploadUrl error:', error.message);
        return createResponse(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

function rewriteMultipartCompletionUrl(requestUrl, uploadInfo) {
    const uploadAction = uploadInfo?.uploadAction;
    if (!uploadAction?.header?.chunk_size || !uploadAction.href) {
        return;
    }

    const originalCompletionUrl = uploadAction.href;
    uploadAction.href = `${requestUrl.origin}/upload/huggingface/completeMultipart?target=${encodeURIComponent(originalCompletionUrl)}`;
}
