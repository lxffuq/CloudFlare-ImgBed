import { createS3Client } from '../utils/storage/s3Client.js';
/* ======= 客户端分块上传处理 ======= */
import { createResponse, checkUploadFormat, selectConsistentChannel, getUploadIp, getIPAddress, buildUniqueFileId, endUpload } from './uploadTools';
import { TelegramAPI } from '../utils/storage/telegramAPI';
import { DiscordAPI } from '../utils/storage/discordAPI';
import { CreateMultipartUploadCommand, UploadPartCommand, AbortMultipartUploadCommand } from "@aws-sdk/client-s3";
import { getDatabase, checkDatabaseConfig } from '../utils/databaseAdapter.js';
import { fetchPageConfig } from '../utils/sysConfig.js';
import { resolveFileType } from '../utils/mimeTypes.js';

// 分块数上限（P1-33/34，与合并侧一致）；前端分块大小与之配套：
// Discord 9MB、其它渠道 16MB，200 块即单文件上限约 1.8–3.2GB。
export const MAX_TOTAL_CHUNKS = 200;
export const CHUNK_SIZE_BY_CHANNEL = { discord: 9437184, default: 16777216 };
const SESSION_TTL_SECONDS = 3600;

// P0-10：校验分块会话归属。会话里存的上传 IP 与当前请求 IP 一致才放行；
// 任一为空（无法确认，如测试环境或 IP 头缺失）时不拦截，避免把正常上传误杀。
// 注意：移动网络切换 IP 会导致同一次上传后续分块被拦，属已知取舍，见汇报。
export function checkSessionOwnership(sessionInfo, request) {
    const sessionIp = sessionInfo?.uploadIp;
    if (!sessionIp) return true;
    const requestIp = getUploadIp(request);
    if (!requestIp) return true;
    return sessionIp === requestIp;
}

function chunkKeyFor(uploadId, chunkIndex) {
    return `chunk_${uploadId}_${chunkIndex.toString().padStart(3, '0')}`;
}

// P1-48：分块 SHA256（前端暂不传每块哈希时跳过；初始化传了 chunkHashes 才校验）
export async function sha256Hex(data) {
    const digest = await crypto.subtle.digest('SHA-256', data);
    return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// P1-32：带版本守卫的分块状态写入。晚到的上传结果（已超时/失败的旧尝试）
// 不得覆盖更新的状态：只有记录仍是本次尝试（uploadStartTime 相同）且处于
// uploading/retrying 时才写。
async function writeChunkStatusIfCurrent(db, chunkKey, attemptStartTime, metadata, value, usingD1) {
    const current = await db.getWithMetadata(chunkKey, { type: 'arrayBuffer' });
    if (!current || !current.metadata) return false;
    if (current.metadata.uploadStartTime !== attemptStartTime) return false;
    if (current.metadata.status !== 'uploading' && current.metadata.status !== 'retrying') return false;
    await db.put(chunkKey, value, { metadata, expirationTtl: SESSION_TTL_SECONDS });
    return true;
}

function isValidChunkIndex(value, totalChunks) {
    return Number.isInteger(value) && value >= 0 && value < totalChunks;
}

// 读 multipart 记录（JSON 解析失败返回 null）
async function readMultipartInfo(db, multipartKey) {
    try {
        const raw = await db.get(multipartKey);
        return raw ? JSON.parse(raw) : null;
    } catch (e) {
        return null;
    }
}

// 等一个已创建好的 multipart 记录（带 uploadId 才算）；超时返回 null。
// P1-37：非 0 分块不再等 60 秒，默认只等 5 秒，等不到就失败由客户端重传。
async function waitForMultipartInfo(db, multipartKey, maxWaitMs = 5000) {
    const deadline = Date.now() + maxWaitMs;
    while (Date.now() < deadline) {
        const info = await readMultipartInfo(db, multipartKey);
        if (info?.uploadId && info.key) return info;
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    return await readMultipartInfo(db, multipartKey).then(info => (info?.uploadId && info.key ? info : null));
}

function parseChunkHashes(raw, totalChunks) {
    if (raw === null || raw === undefined || raw === '') return null;
    try {
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed) || parsed.length !== totalChunks) return { error: 'chunkHashes must be an array matching totalChunks' };
        if (parsed.some(hash => typeof hash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hash))) {
            return { error: 'chunkHashes must be 64-character hex strings' };
        }
        return { hashes: parsed };
    } catch (e) {
        return { error: 'chunkHashes must be valid JSON' };
    }
}

// 初始化分块上传
export async function initializeChunkedUpload(context) {
    const { request, env, url } = context;
    const db = getDatabase(env);

    try {
        // 解析表单数据
        const formdata = await request.formData();

        const originalFileName = formdata.get('originalFileName');
        const originalFileType = resolveFileType(originalFileName, formdata.get('originalFileType'));
        // P1-33/34：totalChunks 必须是 1–200 的整数；NaN/负数/小数/超限直接 400。
        const totalChunks = Number(formdata.get('totalChunks'));

        if (!originalFileName || !originalFileType || !Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > MAX_TOTAL_CHUNKS) {
            return createResponse('Error: Missing initialization parameters', { status: 400 });
        }

        // P1-34/48：fileSize 可选（前端目前不传）；传了就校验：正整数、
        // 不超过“分块数×本渠道分块大小”，且按本渠道分块大小算出的块数必须等于 totalChunks。
        // P1-48：chunkHashes 可选（前端目前不传每块哈希）；传了就校验格式并存入会话供合并核对。
        const uploadChannelForSize = url.searchParams.get('uploadChannel') || 'telegram';
        const chunkSizeForChannel = CHUNK_SIZE_BY_CHANNEL[uploadChannelForSize] || CHUNK_SIZE_BY_CHANNEL.default;
        const rawFileSize = formdata.get('fileSize');
        let fileSize = null;
        if (rawFileSize !== null && rawFileSize !== undefined && rawFileSize !== '') {
            fileSize = Number(rawFileSize);
            if (!Number.isInteger(fileSize) || fileSize <= 0 || fileSize > MAX_TOTAL_CHUNKS * chunkSizeForChannel ||
                Math.ceil(fileSize / chunkSizeForChannel) !== totalChunks) {
                return createResponse('Error: Invalid fileSize for totalChunks', { status: 400 });
            }
        }
        const chunkHashesResult = parseChunkHashes(formdata.get('chunkHashes'), totalChunks);
        if (chunkHashesResult?.error) {
            return createResponse(`Error: ${chunkHashesResult.error}`, { status: 400 });
        }

        const formatError = checkUploadFormat(originalFileName, context.uploadConfig);
        if (formatError) return formatError;

        // 生成唯一的 uploadId
        const timestamp = Date.now();
        const random = Math.random().toString(36).slice(2, 11);
        const uploadId = `upload_${timestamp}_${random}`;

        // 获取上传IP
        const uploadIp = getUploadIp(request);
        const ipAddress = await getIPAddress(env, uploadIp, context.securityConfig);

        // 获取上传渠道
        const uploadChannel = url.searchParams.get('uploadChannel') || 'telegram';
        if (uploadChannel === 'webdav') {
            return createResponse('Error: WebDAV channel does not support chunked uploads. Please use non-chunked upload within your Cloudflare request body limit.', { status: 400 });
        }
        // 获取指定的渠道名称
        const channelName = url.searchParams.get('channelName') || '';

        // 存储上传会话信息
        const sessionInfo = {
            uploadId,
            originalFileName,
            originalFileType,
            totalChunks,
            fileSize,
            chunkHashes: chunkHashesResult?.hashes || null,
            uploadChannel,
            channelName,
            uploadIp,
            ipAddress,
            status: 'initialized',
            createdAt: timestamp,
            expiresAt: timestamp + 3600000 // 1小时过期
        };

        // 保存会话信息
        const sessionKey = `upload_session_${uploadId}`;
        await db.put(sessionKey, JSON.stringify(sessionInfo), {
            expirationTtl: 3600 // 1小时过期
        });

        return createResponse(JSON.stringify({
            success: true,
            uploadId,
            message: 'Chunked upload initialized successfully',
            sessionInfo: {
                uploadId,
                originalFileName,
                totalChunks,
                uploadChannel,
                channelName
            }
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        return createResponse(`Error: Failed to initialize chunked upload - ${error.message}`, { status: 500 });
    }
}

// 处理客户端分块上传
export async function handleChunkUpload(context) {
    const { env, request, url, waitUntil } = context;
    const db = getDatabase(env);

    // 解析表单数据
    const formdata = await request.formData();
    context.formdata = formdata;

    try {
        const chunk = formdata.get('file');
        // P1-33：严格解析，NaN/负数/越界/小数直接 400（parseInt('abc') 得 NaN
        // 旧代码只判 ===null，根本拦不住）。
        const chunkIndex = Number(formdata.get('chunkIndex'));
        const totalChunks = Number(formdata.get('totalChunks'));
        const uploadId = formdata.get('uploadId');
        const originalFileName = formdata.get('originalFileName');
        const originalFileType = resolveFileType(originalFileName, formdata.get('originalFileType'));

        if (!chunk || !Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > MAX_TOTAL_CHUNKS ||
            !isValidChunkIndex(chunkIndex, totalChunks) || !uploadId || !originalFileName || !originalFileType) {
            return createResponse('Error: Missing chunk upload parameters', { status: 400 });
        }

        // 验证上传会话
        const sessionKey = `upload_session_${uploadId}`;
        const sessionData = await db.get(sessionKey);
        if (!sessionData) {
            return createResponse('Error: Invalid or expired upload session', { status: 400 });
        }

        const sessionInfo = JSON.parse(sessionData);

        // P0-10：分块上传校验会话归属
        if (!checkSessionOwnership(sessionInfo, request)) {
            return createResponse('Error: Upload session belongs to another client', { status: 403 });
        }

        // 验证会话信息
        if (sessionInfo.originalFileName !== originalFileName ||
            sessionInfo.totalChunks !== totalChunks) {
            return createResponse('Error: Session parameters mismatch', { status: 400 });
        }

        const formatError = checkUploadFormat(sessionInfo.originalFileName, context.uploadConfig);
        if (formatError) return formatError;

        // 检查会话是否过期
        if (Date.now() > sessionInfo.expiresAt) {
            return createResponse('Error: Upload session expired', { status: 410 });
        }

        // P1-35：渠道与渠道名以初始化会话为准，中途换渠道直接 400。
        // 前端每次请求都带同一套参数（见汇报），不会误伤正常上传。
        const requestedChannel = url.searchParams.get('uploadChannel');
        if (requestedChannel && requestedChannel !== sessionInfo.uploadChannel) {
            return createResponse('Error: uploadChannel does not match the initialized session', { status: 400 });
        }
        const uploadChannel = sessionInfo.uploadChannel || requestedChannel || 'telegram';
        if (uploadChannel === 'webdav') {
            return createResponse('Error: WebDAV channel does not support chunked uploads. Please use non-chunked upload within your Cloudflare request body limit.', { status: 400 });
        }
        const requestedChannelName = url.searchParams.get('channelName');
        if (requestedChannelName && sessionInfo.channelName && requestedChannelName !== sessionInfo.channelName) {
            return createResponse('Error: channelName does not match the initialized session', { status: 400 });
        }
        // 会话建时没指定渠道名、首个分块带了的，把它锁定进会话，后续分块以此为准。
        const channelName = sessionInfo.channelName || requestedChannelName || '';
        if (!sessionInfo.channelName && requestedChannelName) {
            sessionInfo.channelName = requestedChannelName;
            await db.put(sessionKey, JSON.stringify(sessionInfo), { expirationTtl: SESSION_TTL_SECONDS }).catch(() => {});
        }

        // 将渠道名称存入 context
        context.specifiedChannelName = channelName;

        // 立即创建分块记录，标记为"uploading"状态
        const chunkKey = chunkKeyFor(uploadId, chunkIndex);
        const chunkData = await chunk.arrayBuffer();
        const uploadStartTime = Date.now();

        // P1-48：初始化传了每块哈希的，在这里核对本块字节；不符直接 400，
        // 不让坏块入库（前端目前不传哈希，此分支默认跳过）。
        if (sessionInfo.chunkHashes?.[chunkIndex]) {
            const actualHash = await sha256Hex(chunkData);
            if (actualHash !== sessionInfo.chunkHashes[chunkIndex].toLowerCase()) {
                return createResponse(JSON.stringify({
                    error: `Chunk ${chunkIndex} hash mismatch`,
                    chunkIndex,
                    uploadId,
                }), { status: 400, headers: { 'Content-Type': 'application/json' } });
            }
        }

        const initialChunkMetadata = {
            uploadId,
            chunkIndex,
            totalChunks,
            originalFileName,
            originalFileType,
            chunkSize: chunkData.byteLength,
            chunkSha256: sessionInfo.chunkHashes?.[chunkIndex] || null,
            uploadTime: uploadStartTime,
            uploadStartTime: uploadStartTime,
            status: 'uploading',
            uploadChannel,
            channelName,
            timeoutThreshold: uploadStartTime + 60000 // 1分钟超时阈值
        };

        // 立即保存分块记录和数据，设置过期时间
        const { usingD1 } = checkDatabaseConfig(env);
        await db.put(chunkKey, usingD1 ? '' : chunkData, {
            metadata: initialChunkMetadata,
            expirationTtl: 3600 // 1小时过期
        });

        // 同步上传分块到存储端，添加超时保护
        const storageOutcome = await uploadChunkToStorageWithTimeout(context, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType, uploadChannel, usingD1 ? chunkData : undefined, uploadStartTime);

        // P1-31/32：分块接口不再永远返回成功。存储失败/超时时返回 500 并带
        // chunkIndex；前端对单块失败会重试最多 3 次（已核查，见汇报），
        // 因此返回 500 不会破坏现有流程，只会让失败可定位、可重试。
        // D1 下失败分块的字节没有留存，错误里写明需客户端重传该分块。
        const finalRecord = await db.getWithMetadata(chunkKey);
        const finalStatus = finalRecord?.metadata?.status;
        if (!storageOutcome?.success || finalStatus !== 'completed') {
            const detail = finalRecord?.metadata?.error || storageOutcome?.error || 'Chunk upload failed';
            return createResponse(JSON.stringify({
                success: false,
                error: usingD1
                    ? `${detail} (chunk ${chunkIndex} data was not retained, please re-upload this chunk)`
                    : detail,
                chunkIndex,
                uploadId,
                retryable: true,
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        return createResponse(JSON.stringify({
            success: true,
            message: `Chunk ${chunkIndex + 1}/${totalChunks} received and being uploaded`,
            uploadId,
            chunkIndex
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        return createResponse(`Error: Failed to upload chunk - ${error.message}`, { status: 500 });
    }
}

// 处理清理请求
export async function handleCleanupRequest(context, uploadId, totalChunks) {
    try {
        if (!uploadId) {
            return createResponse(JSON.stringify({
                error: 'Missing uploadId parameter'
            }), { status: 400, headers: { 'Content-Type': 'application/json' } });
        }

        // P0-10：清理先验会话归属。会话不存在直接拒绝（以前任何人拿着
        // uploadId 就能删掉别人的在途分块）；IP 与会话里的上传 IP 不一致
        // 也拒绝。前端清理是“尽力而为”（失败只记日志），正常取消上传
        // 仍由同一浏览器发起，不会被误伤。
        const { request, env } = context;
        const db = getDatabase(env);
        const sessionData = await db.get(`upload_session_${uploadId}`);
        if (!sessionData) {
            return createResponse(JSON.stringify({
                error: 'Invalid or expired upload session'
            }), { status: 404, headers: { 'Content-Type': 'application/json' } });
        }
        if (!checkSessionOwnership(JSON.parse(sessionData), request)) {
            return createResponse(JSON.stringify({
                error: 'Upload session belongs to another client'
            }), { status: 403, headers: { 'Content-Type': 'application/json' } });
        }

        // 强制清理所有相关数据
        await forceCleanupUpload(context, uploadId, totalChunks);

        return createResponse(JSON.stringify({
            success: true,
            message: `Cleanup completed for upload ${uploadId}`,
            uploadId: uploadId,
            cleanedChunks: totalChunks
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        return createResponse(JSON.stringify({
            error: `Cleanup failed: ${error.message}`,
            uploadId: uploadId
        }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}

/* ======= 单个分块上传到不同渠道的存储端 ======= */

// 带超时保护的异步上传分块到存储端
// 返回 {success, error?, timedOut?}，调用方据此决定分块接口返回 200 还是 500。
// 超时后不再放任后台上传的结果覆盖状态：超时标记带本次尝试的 uploadStartTime
// 做版本守卫，晚到的成功结果写不进已超时/失败的记录（见 writeChunkStatusIfCurrent）。
// 注意：Telegram/Discord 的 sendFile 不接受取消信号，超时只能做到“不等它、
// 不认它的晚到结果”，无法真正中断已发出的上游请求。
async function uploadChunkToStorageWithTimeout(context, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType, uploadChannel, chunkData, uploadStartTime) {
    const { env } = context;
    const db = getDatabase(env);
    const chunkKey = chunkKeyFor(uploadId, chunkIndex);
    const UPLOAD_TIMEOUT = 180000; // 3分钟超时

    try {
        // 设置超时 Promise
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Upload timeout')), UPLOAD_TIMEOUT);
        });

        // 执行实际上传
        const uploadPromise = uploadChunkToStorage(context, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType, uploadChannel, chunkData, uploadStartTime);

        // 竞速执行
        await Promise.race([uploadPromise, timeoutPromise]);
        return { success: true };

    } catch (error) {
        console.error(`Chunk ${chunkIndex} upload failed or timed out:`, error);

        // 超时或失败时，更新状态为超时/失败（带版本守卫：只改本次尝试的记录）
        try {
            const { usingD1 } = checkDatabaseConfig(env);
            const chunkRecord = await db.getWithMetadata(chunkKey, { type: 'arrayBuffer' });
            if (chunkRecord && chunkRecord.metadata) {
                const isTimeout = error.message === 'Upload timeout';
                const errorMetadata = {
                    ...chunkRecord.metadata,
                    status: isTimeout ? 'timeout' : 'failed',
                    error: error.message,
                    failedTime: Date.now(),
                    isTimeout: isTimeout
                };

                // 保留原始数据以便重试（D1模式下不保存二进制数据，避免SQLITE_TOOBIG）
                await writeChunkStatusIfCurrent(db, chunkKey, uploadStartTime, errorMetadata, usingD1 ? '' : chunkRecord.value, usingD1);
            }
        } catch (metaError) {
            console.error('Failed to save timeout/error metadata:', metaError);
        }
        return { success: false, error: error.message, timedOut: error.message === 'Upload timeout' };
    }
}

// 异步上传分块到存储端，失败自动重试
async function uploadChunkToStorage(context, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType, uploadChannel, chunkData, uploadStartTime) {
    const { env } = context;
    const db = getDatabase(env);

    const chunkKey = chunkKeyFor(uploadId, chunkIndex);

    const MAX_RETRIES = 3;

    try {
        let chunkMetadata;

        if (chunkData !== undefined) {
            const chunkRecord = await db.getWithMetadata(chunkKey);
            chunkMetadata = (chunkRecord && chunkRecord.metadata) ? chunkRecord.metadata : {};
        } else {
            // 从数据库读取分块数据和metadata
            const chunkRecord = await db.getWithMetadata(chunkKey, { type: 'arrayBuffer' });
            if (!chunkRecord || !chunkRecord.value) {
                console.error(`Chunk ${chunkIndex} data not found in database`);
                return;
            }

            chunkData = chunkRecord.value;
            chunkMetadata = chunkRecord.metadata;
        }

        for (let retry = 0; retry < MAX_RETRIES; retry++) {
            // 根据渠道上传分块
            let uploadResult = null;

            if (uploadChannel === 'cfr2') {
                uploadResult = await uploadSingleChunkToR2Multipart(context, chunkData, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType);
            } else if (uploadChannel === 's3') {
                uploadResult = await uploadSingleChunkToS3Multipart(context, chunkData, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType);
            } else if (uploadChannel === 'telegram') {
                uploadResult = await uploadSingleChunkToTelegram(context, chunkData, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType);
            } else if (uploadChannel === 'discord') {
                uploadResult = await uploadSingleChunkToDiscord(context, chunkData, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType);
            }

            if (uploadResult && uploadResult.success) {
                // 上传成功，更新状态并保存上传信息（带版本守卫：若本块已被
                // 标记超时/失败，晚到的成功结果不再覆盖，调用方会返回 500
                // 让客户端重传该分块）
                const updatedMetadata = {
                    ...chunkMetadata,
                    status: 'completed',
                    uploadResult: uploadResult,
                    completedTime: Date.now()
                };

                // 只保存metadata，不保存原始数据，设置过期时间
                await writeChunkStatusIfCurrent(db, chunkKey, uploadStartTime, updatedMetadata, '', checkDatabaseConfig(env).usingD1);

                console.log(`Chunk ${chunkIndex} uploaded successfully to ${uploadChannel}`);

                break;
            } else if (retry === MAX_RETRIES - 1) {
                // 最后一次上传失败，标记为失败状态并保留原始数据以便重试
                const failedMetadata = {
                    ...chunkMetadata,
                    status: 'failed',
                    error: uploadResult ? uploadResult.error : 'Unknown error',
                    failedTime: Date.now()
                };

                // 保留原始数据以便重试（D1模式下不保存二进制数据，避免SQLITE_TOOBIG）
                const { usingD1: isD1 } = checkDatabaseConfig(env);
                await writeChunkStatusIfCurrent(db, chunkKey, uploadStartTime, failedMetadata, isD1 ? '' : chunkData, isD1);

                console.warn(`Chunk ${chunkIndex} upload failed: ${failedMetadata.error}`);
            }
        }

    } catch (error) {
        console.error(`Error uploading chunk ${chunkIndex}:`, error);

        // 发生异常时，确保保留原始数据并标记为失败
        try {
            const { usingD1: isD1 } = checkDatabaseConfig(env);
            const chunkRecord = await db.getWithMetadata(chunkKey, { type: 'arrayBuffer' });
            if (chunkRecord && chunkRecord.metadata) {
                const errorMetadata = {
                    ...chunkRecord.metadata,
                    status: 'failed',
                    error: error.message,
                    failedTime: Date.now()
                };

                // D1模式下不保存二进制数据，避免SQLITE_TOOBIG
                await writeChunkStatusIfCurrent(db, chunkKey, uploadStartTime, errorMetadata, isD1 ? '' : chunkRecord.value, isD1);
            }
        } catch (metaError) {
            console.error('Failed to save error metadata:', metaError);
        }
    }
}

// 上传单个分块到R2 (Multipart Upload)
async function uploadSingleChunkToR2Multipart(context, chunkData, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType) {
    const { env, uploadConfig } = context;
    const db = getDatabase(env);

    try {
        const r2Settings = uploadConfig.cfr2;
        if (!r2Settings.channels || r2Settings.channels.length === 0) {
            return { success: false, error: 'No R2 channel provided' };
        }

        const R2DataBase = env.img_r2;
        const multipartKey = `multipart_${uploadId}`;

        let finalFileId;

        // P1-38：chunk0 先读 multipart 记录，已存在直接复用，不再新建覆盖。
        // 并发重发的 chunk0 用 creating 占位互斥：看到新鲜的 creating 占位
        // 时等它一会儿（等创建完成的记录），过期了才自己创建。
        const existingMultipart = await readMultipartInfo(db, multipartKey);
        if (existingMultipart?.uploadId && existingMultipart.key) {
            finalFileId = existingMultipart.key;
        } else {
            if (existingMultipart?.creating && Date.now() - existingMultipart.createdAt < 30000) {
                const waited = await waitForMultipartInfo(db, multipartKey, 5000);
                if (waited?.uploadId && waited.key) {
                    finalFileId = waited.key;
                }
            }
            if (!finalFileId) {
                // 如果是第一个分块，生成并保存 finalFileId
                if (chunkIndex === 0) {
                    finalFileId = await buildUniqueFileId(context, originalFileName, originalFileType);

                    await db.put(multipartKey, JSON.stringify({ creating: true, createdAt: Date.now() }), {
                        expirationTtl: 3600
                    });
                    let multipartUpload;
                    try {
                        multipartUpload = await R2DataBase.createMultipartUpload(finalFileId, {
                            httpMetadata: { contentType: originalFileType },
                        });
                    } catch (error) {
                        // 创建失败时删掉 creating 占位，否则重试的 chunk0 会
                        // 对着新鲜占位白等 5 秒（占位只防并发重建，不代表创建成功）
                        await db.delete(multipartKey).catch(() => {});
                        throw error;
                    }
                    const multipartInfo = {
                        uploadId: multipartUpload.uploadId,
                        key: finalFileId
                    };

                    // 保存multipart info
                    await db.put(multipartKey, JSON.stringify(multipartInfo), {
                        expirationTtl: 3600 // 1小时过期
                    });
                } else {
                    // P1-37：其它分块只等很短时间（初始化时 multipart 应已由
                    // chunk0 建好；等不到就失败、由客户端重传该分块，不再等 60 秒）。
                    const waited = await waitForMultipartInfo(db, multipartKey, 5000);
                    if (!waited?.uploadId) {
                        return { success: false, error: 'Multipart upload not initialized after waiting' };
                    }
                    finalFileId = waited.key;
                }
            }
        }

        // 获取multipart info
        const multipartInfoData = await db.get(multipartKey);
        if (!multipartInfoData) {
            return { success: false, error: 'Multipart upload not initialized' };
        }

        const multipartInfo = JSON.parse(multipartInfoData);

        // 上传分块
        const multipartUpload = R2DataBase.resumeMultipartUpload(finalFileId, multipartInfo.uploadId);
        const uploadedPart = await multipartUpload.uploadPart(chunkIndex + 1, chunkData);

        if (!uploadedPart || !uploadedPart.etag) {
            throw new Error(`Failed to upload part ${chunkIndex + 1} to R2`);
        }

        return {
            success: true,
            partNumber: chunkIndex + 1,
            etag: uploadedPart.etag,
            size: chunkData.byteLength,
            uploadTime: Date.now(),
            multipartUploadId: multipartInfo.uploadId,
            key: finalFileId
        };

    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// 上传单个分块到S3 (Multipart Upload)
async function uploadSingleChunkToS3Multipart(context, chunkData, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType) {
    const { env, uploadConfig, specifiedChannelName } = context;
    const db = getDatabase(env);

    try {
        const s3Settings = uploadConfig.s3;
        const s3Channels = s3Settings.channels;
        
        // 优先使用指定的渠道名称
        let s3Channel;
        if (specifiedChannelName) {
            s3Channel = s3Channels.find(ch => ch.name === specifiedChannelName);
        }
        if (!s3Channel) {
            s3Channel = selectConsistentChannel(s3Channels, uploadId, s3Settings.loadBalance.enabled);
        }

        console.log(`Uploading S3 chunk ${chunkIndex} for uploadId: ${uploadId}, selected channel: ${s3Channel.name || 'default'}`);

        if (!s3Channel) {
            return { success: false, error: 'No S3 channel provided' };
        }

        const { bucketName } = s3Channel;

        const s3Client = createS3Client(s3Channel);

        const multipartKey = `multipart_${uploadId}`;


        let finalFileId;

        // P1-38/37：与 R2 同款——chunk0 先读记录复用、creating 占位防并发
        // 重建；非 0 分块只等 5 秒，等不到就失败由客户端重传。
        const existingMultipart = await readMultipartInfo(db, multipartKey);
        if (existingMultipart?.uploadId && existingMultipart.key) {
            finalFileId = existingMultipart.key;
        } else {
            if (existingMultipart?.creating && Date.now() - existingMultipart.createdAt < 30000) {
                const waited = await waitForMultipartInfo(db, multipartKey, 5000);
                if (waited?.uploadId && waited.key) {
                    finalFileId = waited.key;
                }
            }
            if (!finalFileId) {
                // 如果是第一个分块，生成并保存 finalFileId
                if (chunkIndex === 0) {
                    finalFileId = await buildUniqueFileId(context, originalFileName, originalFileType);

                    await db.put(multipartKey, JSON.stringify({ creating: true, createdAt: Date.now() }), {
                        expirationTtl: 3600
                    });
                    let createResponse;
                    try {
                        createResponse = await s3Client.send(new CreateMultipartUploadCommand({
                            Bucket: bucketName,
                            Key: finalFileId,
                            ContentType: originalFileType || 'application/octet-stream'
                        }));
                    } catch (error) {
                        // 创建失败时删掉 creating 占位，否则重试的 chunk0 会
                        // 对着新鲜占位白等 5 秒（占位只防并发重建，不代表创建成功）
                        await db.delete(multipartKey).catch(() => {});
                        throw error;
                    }

                    const multipartInfo = {
                        uploadId: createResponse.UploadId,
                        key: finalFileId
                    };

                    // 保存multipart info
                    await db.put(multipartKey, JSON.stringify(multipartInfo), {
                        expirationTtl: 3600 // 1小时过期
                    });
                } else {
                    const waited = await waitForMultipartInfo(db, multipartKey, 5000);
                    if (!waited?.uploadId) {
                        return { success: false, error: 'Multipart upload not initialized after waiting' };
                    }
                    finalFileId = waited.key;
                }
            }
        }

        // 获取multipart info
        const multipartInfoData = await db.get(multipartKey);
        if (!multipartInfoData) {
            return { success: false, error: 'Multipart upload not initialized' };
        }

        const multipartInfo = JSON.parse(multipartInfoData);

        // 上传分块
        const uploadResponse = await s3Client.send(new UploadPartCommand({
            Bucket: bucketName,
            Key: finalFileId,
            PartNumber: chunkIndex + 1,
            UploadId: multipartInfo.uploadId,
            Body: new Uint8Array(chunkData)
        }));

        if (!uploadResponse || !uploadResponse.ETag) {
            throw new Error(`Failed to upload part ${chunkIndex + 1} to S3`);
        }

        return {
            success: true,
            partNumber: chunkIndex + 1,
            etag: uploadResponse.ETag,
            size: chunkData.byteLength,
            uploadTime: Date.now(),
            s3Channel: s3Channel.name,
            multipartUploadId: multipartInfo.uploadId,
            key: finalFileId
        };

    } catch (error) {
        console.error(`S3 chunk upload error (chunk ${chunkIndex}):`, error.message, error.name, error.$metadata);
        return {
            success: false,
            error: error.message
        };
    }
}

// 上传单个分块到Telegram
async function uploadSingleChunkToTelegram(context, chunkData, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType) {
    const { uploadConfig, specifiedChannelName } = context;

    try {
        const tgSettings = uploadConfig.telegram;
        const tgChannels = tgSettings.channels;
        
        // 优先使用指定的渠道名称
        let tgChannel;
        if (specifiedChannelName) {
            tgChannel = tgChannels.find(ch => ch.name === specifiedChannelName);
        }
        if (!tgChannel) {
            tgChannel = selectConsistentChannel(tgChannels, uploadId, tgSettings.loadBalance.enabled);
        }

        console.log(`Uploading Telegram chunk ${chunkIndex} for uploadId: ${uploadId}, selected channel: ${tgChannel.name || 'default'}`);

        if (!tgChannel) {
            return { success: false, error: 'No Telegram channel provided' };
        }

        const tgBotToken = tgChannel.botToken;
        const tgChatId = tgChannel.chatId;
        const tgProxyUrl = tgChannel.proxyUrl || '';

        // 创建分块文件名
        const chunkFileName = `${originalFileName}.part${chunkIndex.toString().padStart(3, '0')}`;
        const chunkBlob = new Blob([chunkData], { type: 'application/octet-stream' });

        // 上传分块到Telegram（支持代理域名）
        const chunkInfo = await uploadChunkToTelegramWithRetry(
            tgBotToken,
            tgChatId,
            tgProxyUrl,
            chunkBlob,
            chunkFileName,
            chunkIndex,
            totalChunks, // 传入正确的totalChunks
            2 // maxRetries
        );

        if (!chunkInfo) {
            return { success: false, error: 'Failed to upload chunk to Telegram' };
        }

        return {
            success: true,
            fileId: chunkInfo.file_id,
            size: chunkInfo.file_size,
            fileName: chunkFileName,
            uploadTime: Date.now(),
            tgChannel: tgChannel.name
        };

    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// 上传单个分块到Discord
async function uploadSingleChunkToDiscord(context, chunkData, chunkIndex, totalChunks, uploadId, originalFileName, originalFileType) {
    const { uploadConfig, specifiedChannelName } = context;

    try {
        const discordSettings = uploadConfig.discord;
        const discordChannels = discordSettings.channels;
        
        // 优先使用指定的渠道名称
        let discordChannel;
        if (specifiedChannelName) {
            discordChannel = discordChannels.find(ch => ch.name === specifiedChannelName);
        }
        if (!discordChannel) {
            discordChannel = selectConsistentChannel(discordChannels, uploadId, discordSettings.loadBalance?.enabled);
        }

        console.log(`Uploading Discord chunk ${chunkIndex} for uploadId: ${uploadId}, selected channel: ${discordChannel.name || 'default'}`);

        if (!discordChannel) {
            return { success: false, error: 'No Discord channel provided' };
        }

        const botToken = discordChannel.botToken;
        const channelId = discordChannel.channelId;

        // 创建分块文件名
        const chunkFileName = `${originalFileName}.part${chunkIndex.toString().padStart(3, '0')}`;
        const chunkBlob = new Blob([chunkData], { type: 'application/octet-stream' });

        // 上传分块到Discord（带重试）
        const chunkInfo = await uploadChunkToDiscordWithRetry(
            botToken,
            channelId,
            chunkBlob,
            chunkFileName,
            chunkIndex,
            totalChunks,
            2 // maxRetries
        );

        if (!chunkInfo) {
            return { success: false, error: 'Failed to upload chunk to Discord' };
        }

        return {
            success: true,
            messageId: chunkInfo.message_id,
            // 注意：不存储 attachmentId 和 url，因为它们会在约24小时后过期
            // 读取时会通过 messageId 获取新的 URL
            size: chunkInfo.file_size,
            fileName: chunkFileName,
            uploadTime: Date.now(),
            discordChannel: discordChannel.name
        };

    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// 将每个分块上传至Discord，支持失败重试和 rate limit 处理
async function uploadChunkToDiscordWithRetry(botToken, channelId, chunkBlob, chunkFileName, chunkIndex, totalChunks, maxRetries = 2) {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            const discordAPI = new DiscordAPI(botToken);

            const response = await discordAPI.sendFile(chunkBlob, channelId, chunkFileName);

            if (!response || !response.id) {
                throw new Error('Invalid Discord response');
            }

            const fileInfo = discordAPI.getFileInfo(response);
            if (!fileInfo) {
                throw new Error('Failed to extract file info from response');
            }

            return fileInfo;

        } catch (error) {
            console.warn(`Discord chunk ${chunkIndex} upload attempt ${attempt + 1} failed:`, error.message);

            // 检查是否是 rate limit (429)
            if (error.message && error.message.includes('429')) {
                // 从错误消息中提取 retry_after，或使用默认值
                const retryAfter = 5000; // 默认等待 5 秒
                console.log(`Discord rate limited, waiting ${retryAfter}ms...`);
                await new Promise(resolve => setTimeout(resolve, retryAfter));
                continue; // 不计入重试次数
            }

            if (attempt === maxRetries - 1) {
                return null; // 最后一次尝试也失败了
            }

            // 指数退避延迟
            await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
        }
    }

    return null;
}

/* ======== 分块合并时与上传相关的工具函数 ======= */

// 重传失败的分块
// 并发重试失败的分块
export async function retryFailedChunks(context, failedChunks, uploadChannel, options = {}) {
    const {
        maxRetries = 5,
        retryTimeout = 60000, // 60秒重试超时
        maxConcurrency = 3, // 最大并发数
        batchSize = 6 // 每批处理的分块数
    } = options;

    if (!failedChunks || failedChunks.length === 0) {
        console.log('No failed chunks to retry');
        return { success: true, results: [] };
    }

    console.log(`Starting concurrent retry for ${failedChunks.length} failed chunks with max concurrency: ${maxConcurrency}`);

    const results = [];
    const chunksToRetry = failedChunks.filter(chunk =>
        chunk.hasData &&
        chunk.status !== 'uploading' &&
        chunk.status !== 'completed'
    );

    if (chunksToRetry.length === 0) {
        console.log('No chunks need retry (all are either uploading, completed, or have no data)');
        return { success: true, results: [] };
    }

    // 分批处理以控制并发
    for (let i = 0; i < chunksToRetry.length; i += batchSize) {
        const batch = chunksToRetry.slice(i, i + batchSize);
        console.log(`Processing batch ${Math.floor(i / batchSize) + 1}: chunks ${batch.map(c => c.index).join(', ')}`);

        // 真正的并发控制：worker 池一次只启动 maxConcurrency 路，
        // 每路完成后再取下一块。原来 batch.map(async...) 会在创建 Promise 的
        // 瞬间全部开始执行，后面的 slice+allSettled 只是分批“等”，并不限流。
        const batchResults = new Array(batch.length);
        let nextIndex = 0;
        const workers = Array.from(
            { length: Math.min(maxConcurrency, batch.length) },
            async () => {
                while (nextIndex < batch.length) {
                    const slot = nextIndex++;
                    try {
                        batchResults[slot] = await retrySingleChunk(context, batch[slot], uploadChannel, maxRetries, retryTimeout);
                    } catch (error) {
                        console.error('Retry task failed:', error);
                        batchResults[slot] = {
                            success: false,
                            chunk: null,
                            error: error?.message || 'Task failed',
                            reason: 'task_error'
                        };
                    }
                }
            }
        );
        await Promise.all(workers);

        results.push(...batchResults);

        // 批次间稍作延迟
        if (i + batchSize < chunksToRetry.length) {
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    }

    // 统计结果
    const successCount = results.filter(r => r.success).length;
    const failureCount = results.filter(r => !r.success).length;

    console.log(`Retry completed: ${successCount} successful, ${failureCount} failed out of ${results.length} chunks`);

    // 记录失败的分块信息
    const failedResults = results.filter(r => !r.success);
    if (failedResults.length > 0) {
        console.warn('Failed chunks:', failedResults.map(r => ({
            index: r.chunk?.index,
            reason: r.reason,
            error: r.error
        })));
    }

    return {
        success: failureCount === 0,
        results,
        summary: {
            total: results.length,
            successful: successCount,
            failed: failureCount,
            failedChunks: failedResults.map(r => r.chunk?.index).filter(Boolean)
        }
    };
}

// 重试单个失败的分块
async function retrySingleChunk(context, chunk, uploadChannel, maxRetries = 5, retryTimeout = 60000) {
    const { env } = context;
    const db = getDatabase(env);

    let retryCount = 0;
    let lastError = null;

    try {
        const chunkRecord = await db.getWithMetadata(chunk.key, { type: 'arrayBuffer' });
        if (!chunkRecord || !chunkRecord.value) {
            console.error(`Chunk ${chunk.index} data missing for retry`);
            return { success: false, chunk, reason: 'data_missing', error: 'Chunk data not found' };
        }

        const chunkData = chunkRecord.value;
        const originalFileName = chunkRecord.metadata?.originalFileName || 'unknown';
        const originalFileType = resolveFileType(originalFileName, chunkRecord.metadata?.originalFileType);
        const uploadId = chunkRecord.metadata?.uploadId;
        const totalChunks = chunkRecord.metadata?.totalChunks || 1;

        // 更新重试状态
        const { usingD1: isD1 } = checkDatabaseConfig(env);
        const retryMetadata = {
            ...chunkRecord.metadata,
            status: 'retrying',
        };

        await db.put(chunk.key, isD1 ? '' : chunkData, {
            metadata: retryMetadata,
            expirationTtl: 3600
        });

        while (retryCount < maxRetries) {
            // 根据渠道重新上传，添加超时保护
            const retryPromise = (async () => {
                if (uploadChannel === 'cfr2') {
                    return await uploadSingleChunkToR2Multipart(context, chunkData, chunk.index, totalChunks, uploadId, originalFileName, originalFileType);
                } else if (uploadChannel === 's3') {
                    return await uploadSingleChunkToS3Multipart(context, chunkData, chunk.index, totalChunks, uploadId, originalFileName, originalFileType);
                } else if (uploadChannel === 'telegram') {
                    return await uploadSingleChunkToTelegram(context, chunkData, chunk.index, totalChunks, uploadId, originalFileName, originalFileType);
                } else if (uploadChannel === 'discord') {
                    return await uploadSingleChunkToDiscord(context, chunkData, chunk.index, totalChunks, uploadId, originalFileName, originalFileType);
                }
                return null;
            })();

            const timeoutPromise = new Promise((resolve) => {
                setTimeout(() => resolve({
                    success: false,
                    error: 'Retry timeout'
                }), retryTimeout);
            });

            const uploadResult = await Promise.race([retryPromise, timeoutPromise]);

            if (uploadResult && uploadResult.success) {
                // 更新状态为成功
                const updatedMetadata = {
                    ...chunkRecord.metadata,
                    status: 'completed',
                    uploadResult: uploadResult,
                    retryCount: retryCount + 1,
                    completedTime: Date.now()
                };

                // 删除原始数据，只保留上传结果，设置过期时间
                await db.put(chunk.key, '', {
                    metadata: updatedMetadata,
                    expirationTtl: 3600 // 1小时过期
                });

                console.log(`Chunk ${chunk.index} retry successful after ${retryCount + 1} attempts`);
                return { success: true, chunk, retryCount: retryCount + 1 };
            } else if (retryCount === maxRetries - 1) {
                throw new Error(uploadResult?.error || 'Unknown retry error');
            }

            retryCount++;
            lastError = uploadResult?.error || 'Unknown error';
            console.warn(`Chunk ${chunk.index} retry ${retryCount} failed: ${lastError}`);
        }
    } catch (error) {
        lastError = error;
        const isTimeout = error.message === 'Retry timeout';
        console.warn(`Chunk ${chunk.index} retry ${retryCount} ${isTimeout ? 'timed out' : 'failed'}: ${error.message}`);

        // 更新重试失败状态
        try {
            const { usingD1: isD1Retry } = checkDatabaseConfig(env);
            const chunkRecord = await db.getWithMetadata(chunk.key, { type: 'arrayBuffer' });
            if (chunkRecord) {
                const failedRetryMetadata = {
                    ...chunkRecord.metadata,
                    status: isTimeout ? 'retry_timeout' : 'retry_failed'
                };

                // D1模式下不保存二进制数据，避免SQLITE_TOOBIG
                await db.put(chunk.key, isD1Retry ? '' : chunkRecord.value, {
                    metadata: failedRetryMetadata,
                    expirationTtl: 3600
                });
            }
        } catch (metaError) {
            console.error(`Failed to update retry error metadata for chunk ${chunk.index}:`, metaError);
        }

        if (retryCount < maxRetries) {
            // 指数退避延迟
            const delay = Math.min(1000 * Math.pow(2, retryCount - 1), 10000);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }

    console.error(`Chunk ${chunk.index} failed after ${maxRetries} retry attempts`);
    return { success: false, chunk, retryCount, error: lastError?.message || 'Max retries exceeded' };
}


// 清理失败的multipart upload
export async function cleanupFailedMultipartUploads(context, uploadId, uploadChannel) {
    const { env, uploadConfig } = context;
    const db = getDatabase(env);

    try {
        const multipartKey = `multipart_${uploadId}`;
        const multipartInfoData = await db.get(multipartKey);

        if (!multipartInfoData) {
            return; // 没有multipart upload需要清理
        }

        const multipartInfo = JSON.parse(multipartInfoData);

        if (uploadChannel === 'cfr2') {
            // 清理R2 multipart upload
            const R2DataBase = env.img_r2;
            const multipartUpload = R2DataBase.resumeMultipartUpload(multipartInfo.key, multipartInfo.uploadId);
            await multipartUpload.abort();

        } else if (uploadChannel === 's3') {
            // 清理S3 multipart upload
            const s3Settings = uploadConfig.s3;
            const s3Channels = s3Settings.channels;
            
            // 优先使用指定的渠道名称
            let s3Channel;
            const specifiedChannelName = context.specifiedChannelName;
            if (specifiedChannelName) {
                s3Channel = s3Channels.find(ch => ch.name === specifiedChannelName);
            }
            if (!s3Channel) {
                s3Channel = selectConsistentChannel(s3Channels, uploadId, s3Settings.loadBalance.enabled);
            }

            if (s3Channel) {
                const { bucketName } = s3Channel;

                const s3Client = createS3Client(s3Channel);

                await s3Client.send(new AbortMultipartUploadCommand({
                    Bucket: bucketName,
                    Key: multipartInfo.key,
                    UploadId: multipartInfo.uploadId
                }));
            }
        }

        // 清理multipart info
        await db.delete(multipartKey);
        console.log(`Cleaned up failed multipart upload for ${uploadId}`);

    } catch (error) {
        console.error(`Failed to cleanup multipart upload for ${uploadId}:`, error);
    }
}


// 检查分块上传状态
export async function checkChunkUploadStatuses(env, uploadId, totalChunks) {
    const chunkStatuses = [];
    const currentTime = Date.now();

    const db = getDatabase(env);

    for (let i = 0; i < totalChunks; i++) {
        const chunkKey = `chunk_${uploadId}_${i.toString().padStart(3, '0')}`;
        try {
            const chunkRecord = await db.getWithMetadata(chunkKey, { type: 'arrayBuffer' });
            if (chunkRecord && chunkRecord.metadata) {
                let status = chunkRecord.metadata.status || 'unknown';

                // 检查上传超时：如果状态是 uploading 但超过了超时阈值，标记为超时
                if (status === 'uploading' && chunkRecord.metadata.timeoutThreshold && currentTime > chunkRecord.metadata.timeoutThreshold) {
                    status = 'timeout';

                    // 更新状态为超时
                    const { usingD1: isD1Status } = checkDatabaseConfig(env);
                    const timeoutMetadata = {
                        ...chunkRecord.metadata,
                        status: 'timeout',
                        error: 'Upload timeout detected',
                        timeoutDetectedTime: currentTime
                    };

                    // D1模式下不保存二进制数据，避免SQLITE_TOOBIG
                    await db.put(chunkKey, isD1Status ? '' : chunkRecord.value, {
                        metadata: timeoutMetadata,
                        expirationTtl: 3600
                    }).catch(err => console.warn(`Failed to update timeout status for chunk ${i}:`, err));
                }

                let hasData = false;
                if (status === 'completed') {
                    // 已完成的分块，不存储原始数据
                    hasData = false;
                } else if (status === 'uploading' || status === 'failed' || status === 'timeout') {
                    // 正在上传、失败或超时的分块通过原始数据判断
                    hasData = (chunkRecord.value && chunkRecord.value.byteLength > 0);
                } else {
                    // 其他状态也检查是否有数据
                    hasData = (chunkRecord.value && chunkRecord.value.byteLength > 0);
                }

                chunkStatuses.push({
                    index: i,
                    key: chunkKey,
                    status: status,
                    uploadResult: chunkRecord.metadata.uploadResult,
                    error: chunkRecord.metadata.error,
                    hasData: hasData,
                    chunkSize: chunkRecord.metadata.chunkSize,
                    chunkSha256: chunkRecord.metadata.chunkSha256,
                    uploadTime: chunkRecord.metadata.uploadTime,
                    uploadStartTime: chunkRecord.metadata.uploadStartTime,
                    timeoutThreshold: chunkRecord.metadata.timeoutThreshold,
                    uploadChannel: chunkRecord.metadata.uploadChannel,
                    isTimeout: status === 'timeout'
                });
            } else {
                chunkStatuses.push({
                    index: i,
                    key: chunkKey,
                    status: 'missing',
                    hasData: false
                });
            }
        } catch (error) {
            chunkStatuses.push({
                index: i,
                key: chunkKey,
                status: 'error',
                error: error.message,
                hasData: false
            });
        }
    }

    return chunkStatuses;
}


// 清理临时分块数据
export async function cleanupChunkData(env, uploadId, totalChunks) {
    try {
        const db = getDatabase(env);

        for (let i = 0; i < totalChunks; i++) {
            const chunkKey = `chunk_${uploadId}_${i.toString().padStart(3, '0')}`;

            // 删除数据库中的分块记录
            await db.delete(chunkKey);
        }

        // 清理multipart info（如果存在）
        const multipartKey = `multipart_${uploadId}`;
        await db.delete(multipartKey);

    } catch (cleanupError) {
        console.warn('Failed to cleanup chunk data:', cleanupError);
    }
}

// 清理上传会话
export async function cleanupUploadSession(env, uploadId) {
    try {
        const db = getDatabase(env);

        const sessionKey = `upload_session_${uploadId}`;
        await db.delete(sessionKey);
        console.log(`Cleaned up upload session for ${uploadId}`);
    } catch (cleanupError) {
        console.warn('Failed to cleanup upload session:', cleanupError);
    }
}

// 强制清理所有相关数据（用于彻底清理失败的上传）
export async function forceCleanupUpload(context, uploadId, totalChunks) {
    const { env } = context;
    const db = getDatabase(env);

    try {
        // 读取 session 信息
        const sessionKey = `upload_session_${uploadId}`;
        const sessionRecord = await db.get(sessionKey);
        const uploadChannel = sessionRecord ? JSON.parse(sessionRecord).uploadChannel : 'cfr2'; // 默认使用 cfr2

        // 清理 multipart upload信息
        await cleanupFailedMultipartUploads(context, uploadId, uploadChannel);

        const cleanupPromises = [];

        // 清理所有分块
        for (let i = 0; i < totalChunks; i++) {
            const chunkKey = `chunk_${uploadId}_${i.toString().padStart(3, '0')}`;
            cleanupPromises.push(db.delete(chunkKey).catch(err =>
                console.warn(`Failed to delete chunk ${i}:`, err)
            ));
        }

        // 清理相关的键
        const keysToCleanup = [
            `upload_session_${uploadId}`,
            `multipart_${uploadId}`
        ];

        keysToCleanup.forEach(key => {
            cleanupPromises.push(db.delete(key).catch(err =>
                console.warn(`Failed to delete key ${key}:`, err)
            ));
        });

        await Promise.allSettled(cleanupPromises);
        console.log(`Force cleanup completed for ${uploadId}`);

    } catch (cleanupError) {
        console.warn('Failed to force cleanup upload:', cleanupError);
    }
}

/* ======= 单个大文件大文件分块上传到Telegram ======= */
export async function uploadLargeFileToTelegram(context, file, fullId, metadata, fileName, fileType, returnLink, tgBotToken, tgChatId, tgChannel) {
    const { env, waitUntil } = context;
    const db = getDatabase(env);

    const CHUNK_SIZE = 16 * 1024 * 1024; // 16MB (TG Bot getFile download limit: 20MB, leave 4MB safety margin)
    const fileSize = file.size;
    const totalChunks = Math.ceil(fileSize / CHUNK_SIZE);

    // 为了避免CPU超时，限制最大分片数（考虑Cloudflare Worker的CPU时间限制）
    if (totalChunks > 50) {
        return createResponse('Error: File too large (exceeds 1GB limit)', { status: 413 });
    }

    const chunks = [];
    const uploadedChunks = [];

    try {
        // 分片上传，每10个分片做一次微小延迟以避免CPU超时
        for (let i = 0; i < totalChunks; i++) {
            const start = i * CHUNK_SIZE;
            const end = Math.min(start + CHUNK_SIZE, fileSize);
            const chunkBlob = file.slice(start, end);

            // 生成分片文件名
            const chunkFileName = `${fileName}.part${i.toString().padStart(3, '0')}`;

            // 上传分片（带重试机制）
            const tgProxyUrl = tgChannel.proxyUrl || '';
            const chunkInfo = await uploadChunkToTelegramWithRetry(
                tgBotToken,
                tgChatId,
                tgProxyUrl,
                chunkBlob,
                chunkFileName,
                i,
                totalChunks
            );

            if (!chunkInfo) {
                throw new Error(`Failed to upload chunk ${i + 1}/${totalChunks} after retries`);
            }

            // 验证分片信息完整性
            if (!chunkInfo.file_id || !chunkInfo.file_size) {
                throw new Error(`Invalid chunk info for chunk ${i + 1}/${totalChunks}`);
            }

            chunks.push({
                index: i,
                fileId: chunkInfo.file_id,
                size: chunkInfo.file_size,
                fileName: chunkFileName
            });

            uploadedChunks.push(chunkInfo.file_id);

            // 每10个分片检查一下，添加微小延迟避免CPU限制
            if (i > 0 && i % 10 === 0) {
                await new Promise(resolve => setTimeout(resolve, 50)); // 50ms延迟
            }
        }

        // 所有分片上传成功，更新metadata
        metadata.Channel = "TelegramNew";
        metadata.ChannelName = tgChannel.name;
        metadata.IsChunked = true;
        metadata.TotalChunks = totalChunks;
        metadata.FileSize = (fileSize / 1024 / 1024).toFixed(2);


        // 将分片信息存储到value中
        const chunksData = JSON.stringify(chunks);

        // 验证分片完整性
        if (chunks.length !== totalChunks) {
            throw new Error(`Chunk count mismatch: expected ${totalChunks}, got ${chunks.length}`);
        }

        // 写入最终的数据库记录，分片信息作为value
        await db.put(fullId, chunksData, { metadata });

        // 异步结束上传
        waitUntil(endUpload(context, fullId, metadata));

        // 构建公开访问链接（使用 urlPrefix 配置）
        const pageConfig = await fetchPageConfig(env);
        const urlPrefixConfig = pageConfig.config?.find(c => c.id === 'urlPrefix');
        const urlPrefix = urlPrefixConfig?.value || '';
        const responseBody = [{ 'src': returnLink }];
        if (urlPrefix) {
            responseBody[0].publicUrl = `${urlPrefix.replace(/\/+$/, '')}/${fullId}`;
        }
        if (metadata.ExpiresAt) {
            responseBody[0].expiresAt = metadata.ExpiresAt;
        }

        return createResponse(
            JSON.stringify(responseBody),
            {
                status: 200,
                headers: {
                    'Content-Type': 'application/json',
                }
            }
        );

    } catch (error) {
        return createResponse(`Telegram Channel Error: Large file upload failed - ${error.message}`, { status: 500 });
    }
}

// 将每个分块上传至Telegram，支持失败重试（支持代理域名）
async function uploadChunkToTelegramWithRetry(tgBotToken, tgChatId, tgProxyUrl, chunkBlob, chunkFileName, chunkIndex, totalChunks, maxRetries = 2) {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            const tgAPI = new TelegramAPI(tgBotToken, tgProxyUrl);

            const caption = `Part ${chunkIndex + 1}/${totalChunks}`;

            const response = await tgAPI.sendFile(chunkBlob, tgChatId, 'sendDocument', 'document', caption, chunkFileName);
            if (!response.ok) {
                throw new Error(response.description || 'Telegram API error');
            }

            const fileInfo = tgAPI.getFileInfo(response);
            if (!fileInfo) {
                throw new Error('Failed to extract file info from response');
            }

            return fileInfo;

        } catch (error) {
            console.warn(`Chunk ${chunkIndex} upload attempt ${attempt + 1} failed:`, error.message);

            if (attempt === maxRetries - 1) {
                return null; // 最后一次尝试也失败了
            }

            // 减少重试等待时间以节省CPU时间
            await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
        }
    }

    return null;
}
