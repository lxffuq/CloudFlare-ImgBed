import { createS3Client } from '../utils/storage/s3Client.js';
/* ========== 分块合并处理 ========== */
import { createResponse, createUploadResponse, checkUploadFormat, getUploadIp, getIPAddress, selectConsistentChannel, buildUniqueFileId, endUpload, sanitizeUploadFolder, isFileIdReserved } from './uploadTools';
import { retryFailedChunks, cleanupFailedMultipartUploads, checkChunkUploadStatuses, cleanupChunkData, cleanupUploadSession, checkSessionOwnership, MAX_TOTAL_CHUNKS } from './chunkUpload';
import { CompleteMultipartUploadCommand } from "@aws-sdk/client-s3";
import { getDatabase } from '../utils/databaseAdapter.js';
import { fetchPageConfig } from '../utils/sysConfig.js';
import { resolveFileType } from '../utils/mimeTypes.js';
import { resolveUploadExpiry } from '../utils/fileExpiryService.js';

// P0-12：已合并结果的记录键。合并成功后先写这条、再清会话与分块；
// 客户端超时重发合并时直接返回第一次的结果，不再拼出第二个文件。
function mergeResultKey(uploadId) {
    return `merge_result_${uploadId}`;
}

// P0-12/P1-36：合并失败只清 merging 占位，分块与会话一律保留到会话过期，
// 供用户重试合并（以前失败就全清，重试只能从头传）。
async function clearMergingFlag(env, uploadId) {
    try {
        const db = getDatabase(env);
        const sessionKey = `upload_session_${uploadId}`;
        const sessionData = await db.get(sessionKey);
        if (!sessionData) return;
        const sessionInfo = JSON.parse(sessionData);
        if (!sessionInfo.merging) return;
        delete sessionInfo.merging;
        await db.put(sessionKey, JSON.stringify(sessionInfo), { expirationTtl: 3600 });
    } catch (error) {
        console.warn(`Failed to clear merging flag for ${uploadId}:`, error);
    }
}

// 处理分块合并
export async function handleChunkMerge(context) {
    const { request, env, url, waitUntil } = context;
    const db = getDatabase(env);

    // 解析表单数据
    const formdata = await request.formData();
    context.formdata = formdata;

    let uploadId, totalChunks, originalFileName, originalFileType, uploadChannel;
    try {
        uploadId = formdata.get('uploadId');
        // P1-33/34：totalChunks 必须是 1–200 的整数
        totalChunks = Number(formdata.get('totalChunks'));
        originalFileName = formdata.get('originalFileName');
        originalFileType = formdata.get('originalFileType');

        if (!uploadId || !Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > MAX_TOTAL_CHUNKS || !originalFileName) {
            return createResponse('Error: Missing merge parameters', { status: 400 });
        }

        // P0-12：已合并过直接返回第一次的结果（客户端超时重发合并时幂等）
        const previousResultRaw = await db.get(mergeResultKey(uploadId));
        if (previousResultRaw) {
            try {
                const previousResult = JSON.parse(previousResultRaw);
                if (Array.isArray(previousResult?.result)) {
                    return createUploadResponse(context, previousResult.result);
                }
            } catch (e) {
                // 记录损坏时继续走正常合并流程
            }
        }

        // 验证上传会话
        const sessionKey = `upload_session_${uploadId}`;
        const sessionData = await db.get(sessionKey);
        if (!sessionData) {
            return createResponse('Error: Invalid or expired upload session', { status: 400 });
        }

        const sessionInfo = JSON.parse(sessionData);

        // P0-10：合并校验会话归属
        if (!checkSessionOwnership(sessionInfo, request)) {
            return createResponse('Error: Upload session belongs to another client', { status: 403 });
        }

        // P0-12：合并前用会话记录原子占位 merging（带过期）。已有未过期的
        // 合并在跑时直接 409，不让两次并发合并各拼出一个文件。
        // 注：KV/D1 没有 CAS，占位只能把竞态窗口缩得很小，残余并发见汇报。
        if (sessionInfo.merging && sessionInfo.merging.expiresAt > Date.now()) {
            return createResponse('Error: Merge already in progress', { status: 409 });
        }
        sessionInfo.merging = { startedAt: Date.now(), expiresAt: Date.now() + 300000 };
        await db.put(sessionKey, JSON.stringify(sessionInfo), { expirationTtl: 3600 });

        // 未重复发送类型时沿用会话中的明确类型，再对通用值按文件名兜底。
        originalFileType = resolveFileType(originalFileName, originalFileType || sessionInfo.originalFileType);

        // 验证会话信息
        if (sessionInfo.originalFileName !== originalFileName ||
            sessionInfo.totalChunks !== totalChunks) {
            await clearMergingFlag(env, uploadId);
            return createResponse('Error: Session parameters mismatch', { status: 400 });
        }

        const formatError = checkUploadFormat(sessionInfo.originalFileName, context.uploadConfig);
        if (formatError) {
            await clearMergingFlag(env, uploadId);
            return formatError;
        }

        // 检查会话是否过期
        if (Date.now() > sessionInfo.expiresAt) {
            await clearMergingFlag(env, uploadId);
            return createResponse('Error: Upload session expired', { status: 410 });
        }

        // P1-35：渠道与渠道名以初始化会话为准，中途换渠道直接 400
        const requestedChannel = url.searchParams.get('uploadChannel');
        if (requestedChannel && requestedChannel !== sessionInfo.uploadChannel) {
            await clearMergingFlag(env, uploadId);
            return createResponse('Error: uploadChannel does not match the initialized session', { status: 400 });
        }
        const requestedChannelName = url.searchParams.get('channelName');
        if (requestedChannelName && sessionInfo.channelName && requestedChannelName !== sessionInfo.channelName) {
            await clearMergingFlag(env, uploadId);
            return createResponse('Error: channelName does not match the initialized session', { status: 400 });
        }
        // 使用会话中的上传渠道，或者从URL参数获取
        uploadChannel = sessionInfo.uploadChannel || requestedChannel || 'telegram';
        if (uploadChannel === 'webdav') {
            return createResponse('Error: WebDAV channel does not support chunked uploads. Please use non-chunked upload within your Cloudflare request body limit.', { status: 400 });
        }

        // 获取指定的渠道名称（优先URL参数，其次会话信息）
        const channelName = sessionInfo.channelName || requestedChannelName || '';
        context.specifiedChannelName = channelName;

        // 文件有效期由后端按设置决定（合并请求需携带与初始化时相同的 expire 参数）
        const expiry = await resolveUploadExpiry(context);
        if (expiry.error) {
            await clearMergingFlag(env, uploadId);
            return createResponse(expiry.error, { status: 400 });
        }
        context.fileExpiresAt = expiry.expiresAt;

        // 检查分块上传状态
        const chunkStatuses = await checkChunkUploadStatuses(env, uploadId, totalChunks);

        // 输出初始状态摘要
        const initialStatusSummary = chunkStatuses.reduce((acc, chunk) => {
            acc[chunk.status] = (acc[chunk.status] || 0) + 1;
            return acc;
        }, {});
        console.log(`Initial chunk status summary: ${JSON.stringify(initialStatusSummary)}`);

        // P1-36：还有分块在传时合并返回 409“仍在上传”，不要清数据
        if (chunkStatuses.some(chunk => chunk.status === 'uploading' || chunk.status === 'retrying')) {
            await clearMergingFlag(env, uploadId);
            return createResponse('Error: Chunks are still uploading', { status: 409 });
        }

        // 开始合并处理
        return await startMerge(context, uploadId, totalChunks, originalFileName, originalFileType, uploadChannel);

    } catch (error) {
        // 合并失败保留分块与会话，只清 merging 占位，供用户重试合并
        await clearMergingFlag(env, uploadId);

        return createResponse(`Error: Failed to merge chunks - ${error.message}`, { status: 500 });
    }
}

// 开始合并处理
async function startMerge(context, uploadId, totalChunks, originalFileName, originalFileType, uploadChannel) {
    const { env } = context;
    const db = getDatabase(env);

    try {
        // 合并任务状态输出
        const mergeStatus = {
            uploadId,
            status: 'processing',
            progress: 0,
            totalChunks,
            originalFileName,
            originalFileType,
            uploadChannel,
            createdAt: Date.now(),
            message: 'Starting merge process...'
        };
        console.log(`Merge status: ${JSON.stringify(mergeStatus)}`);

        // 同步执行合并
        const result = await handleChannelBasedMerge(context, uploadId, totalChunks, originalFileName, originalFileType, uploadChannel);

        if (result.success) {
            // 构建公开访问链接（使用 urlPrefix 配置）
            if (result.result && result.result.length > 0) {
                const src = result.result[0].src;
                const fileName = src.startsWith('/file/') ? src.slice(6) : src.split('/file/').pop();
                const pageConfig = await fetchPageConfig(env);
                const urlPrefixConfig = pageConfig.config?.find(c => c.id === 'urlPrefix');
                const urlPrefix = urlPrefixConfig?.value || '';
                if (urlPrefix) {
                    result.result[0].publicUrl = `${urlPrefix.replace(/\/+$/, '')}/${fileName}`;
                }
                if (context.fileExpiresAt) {
                    result.result[0].expiresAt = context.fileExpiresAt;
                }
            }

            // P0-12：先把合并结果记下来、再清会话与分块，重发合并直接返回这条
            await db.put(`merge_result_${uploadId}`, JSON.stringify({ result: result.result }), {
                expirationTtl: 3600
            });

            // 清理临时分块数据
            await cleanupChunkData(env, uploadId, totalChunks);

            // 清理上传会话
            await cleanupUploadSession(env, uploadId);

            return createUploadResponse(context, result.result);
        } else {
            throw new Error(result.error || 'Merge failed');
        }

    } catch (error) {
        // P1-36：合并失败保留分块、会话与 multipart，只清 merging 占位，
        // 供用户重试合并（以前失败就全清，重试只能从头传）
        await clearMergingFlag(env, uploadId);

        return createResponse(`Error: Failed to merge chunks - ${error.message}`, { status: 500 });
    }
}

// 基于渠道的合并处理
async function handleChannelBasedMerge(context, uploadId, totalChunks, originalFileName, originalFileType, uploadChannel) {
    const { request, env, url } = context;
    const db = getDatabase(env);

    try {
        // 获得上传IP
        const uploadIp = getUploadIp(request);

        const normalizedFolder = sanitizeUploadFolder(url.searchParams.get('uploadFolder') || '');

        // 构建基础metadata
        const metadata = {
            FileName: originalFileName,
            FileType: originalFileType,
            FileSize: '0', // 会在最终合并后更新
            UploadIP: uploadIp,
            UploadAddress: await getIPAddress(env, uploadIp, context.securityConfig),
            ListType: "None",
            TimeStamp: Date.now(),
            Label: "None",
            Directory: normalizedFolder === '' ? '' : normalizedFolder + '/',
            Tags: []
        };
        if (context.fileExpiresAt) {
            metadata.ExpiresAt = context.fileExpiresAt;
        }

        // 收集所有已上传的分块信息
        const chunkStatuses = await checkChunkUploadStatuses(env, uploadId, totalChunks);
        let completedChunks = chunkStatuses.filter(chunk => chunk.status === 'completed');
        let uploadingChunks = chunkStatuses.filter(chunk =>
            chunk.status === 'uploading' ||
            chunk.status === 'retrying'
        );
        let failedChunks = chunkStatuses.filter(chunk =>
            chunk.status === 'failed' ||
            chunk.status === 'timeout'
        );

        // 统计不同状态的分块
        const statusSummary = chunkStatuses.reduce((acc, chunk) => {
            acc[chunk.status] = (acc[chunk.status] || 0) + 1;
            return acc;
        }, {});

        console.log(`Chunk status summary: ${JSON.stringify(statusSummary)}`);

        // 如果有失败的分块，尝试重试
        if (failedChunks.length > 0) {
            console.log(`Retrying ${failedChunks.length} failed chunks...`);
            // 同步重试（await）
            await retryFailedChunks(context, failedChunks, uploadChannel);
        }

        // 重新检查状态
        const updatedStatuses = await checkChunkUploadStatuses(env, uploadId, totalChunks);
        completedChunks = updatedStatuses.filter(chunk => chunk.status === 'completed');

        // 最终检查是否所有分块都完成
        if (completedChunks.length !== totalChunks) {
            // 获取最新的状态信息
            const finalStatuses = await checkChunkUploadStatuses(env, uploadId, totalChunks);
            const finalStatusSummary = finalStatuses.reduce((acc, chunk) => {
                acc[chunk.status] = (acc[chunk.status] || 0) + 1;
                return acc;
            }, {});

            throw new Error(`Only ${completedChunks.length}/${totalChunks} chunks completed successfully. Final status: ${JSON.stringify(finalStatusSummary)}`);
        }

        // P1-35：合并前校验每个 completed 分块含有所选渠道必需字段，
        // 缺失即报错不写库（中途换渠道拼出的死链到此为止）
        const requiredFields = uploadChannel === 'cfr2' || uploadChannel === 's3'
            ? ['etag', 'partNumber']
            : uploadChannel === 'telegram' ? ['fileId']
            : uploadChannel === 'discord' ? ['messageId'] : [];
        for (const chunk of completedChunks) {
            for (const field of requiredFields) {
                if (!chunk.uploadResult || chunk.uploadResult[field] === undefined || chunk.uploadResult[field] === null) {
                    throw new Error(`Chunk ${chunk.index} is missing ${field} for ${uploadChannel}`);
                }
            }
        }

        // P1-48：逐块核对大小。每块 uploadResult.size 必须与上传时记的
        // chunkSize 一致；除最后一块外各块大小必须相等（前端均匀切片）；
        // 会话里有 fileSize 时总和必须等于它；初始化传了 chunkHashes 的
        // 逐块核对哈希。前端目前不传每块哈希，哈希核对默认跳过，只做大小核对。
        for (const chunk of completedChunks) {
            if (chunk.chunkSize !== undefined && chunk.chunkSize <= 0) {
                throw new Error(`Chunk ${chunk.index} has invalid size`);
            }
            if (chunk.chunkSize !== undefined && chunk.uploadResult?.size !== undefined &&
                chunk.uploadResult.size !== chunk.chunkSize) {
                throw new Error(`Chunk ${chunk.index} size mismatch: expected ${chunk.chunkSize}, got ${chunk.uploadResult.size}`);
            }
        }
        const sortedForSizeCheck = [...completedChunks].sort((a, b) => a.index - b.index);
        for (let i = 0; i + 1 < sortedForSizeCheck.length; i++) {
            const sizeA = sortedForSizeCheck[i].chunkSize;
            const sizeB = sortedForSizeCheck[i + 1].chunkSize;
            if (sizeA !== undefined && sizeB !== undefined && sizeA !== sizeB) {
                throw new Error(`Chunk ${sortedForSizeCheck[i + 1].index} size ${sizeB} differs from previous chunks (${sizeA}); chunks other than the last must be equal size`);
            }
        }
        const sessionRawForMerge = await db.get(`upload_session_${uploadId}`);
        const sessionForMerge = sessionRawForMerge ? JSON.parse(sessionRawForMerge) : null;
        if (sessionForMerge?.fileSize) {
            const totalSize = completedChunks.reduce((sum, chunk) => sum + (chunk.uploadResult?.size ?? chunk.chunkSize ?? 0), 0);
            if (totalSize !== sessionForMerge.fileSize) {
                throw new Error(`Total size mismatch: expected ${sessionForMerge.fileSize}, got ${totalSize}`);
            }
        }
        if (sessionForMerge?.chunkHashes) {
            for (const chunk of completedChunks) {
                const expectedHash = sessionForMerge.chunkHashes[chunk.index];
                if (expectedHash && chunk.chunkSha256 && chunk.chunkSha256.toLowerCase() !== expectedHash.toLowerCase()) {
                    throw new Error(`Chunk ${chunk.index} hash mismatch`);
                }
            }
        }

        // 根据渠道合并分块信息
        let result;
        if (uploadChannel === 'cfr2') {
            result = await mergeR2ChunksInfo(context, uploadId, completedChunks, metadata);
        } else if (uploadChannel === 's3') {
            result = await mergeS3ChunksInfo(context, uploadId, completedChunks, metadata);
        } else if (uploadChannel === 'telegram') {
            result = await mergeTelegramChunksInfo(context, uploadId, completedChunks, metadata);
        } else if (uploadChannel === 'discord') {
            result = await mergeDiscordChunksInfo(context, uploadId, completedChunks, metadata);
        } else {
            throw new Error(`Unsupported upload channel: ${uploadChannel}`);
        }

        return result;

    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

// 合并R2分块信息
async function mergeR2ChunksInfo(context, uploadId, completedChunks, metadata) {
    const { env, waitUntil, url, specifiedChannelName } = context;
    const db = getDatabase(env);

    try {
        const R2DataBase = env.img_r2;
        const multipartKey = `multipart_${uploadId}`;

        // 获取multipart info
        const multipartInfoData = await db.get(multipartKey);
        if (!multipartInfoData) {
            throw new Error('Multipart upload info not found');
        }

        const multipartInfo = JSON.parse(multipartInfoData);

        // 组织所有分块
        const sortedChunks = completedChunks.sort((a, b) => a.index - b.index);
        const parts = [];

        for (const chunk of sortedChunks) {
            const part = {
                etag: chunk.uploadResult.etag,
                partNumber: chunk.uploadResult.partNumber,
            };
            parts.push(part);
        }

        // 完成multipart upload
        const multipartUpload = R2DataBase.resumeMultipartUpload(multipartInfo.key, multipartInfo.uploadId);
        await multipartUpload.complete(parts);

        // 计算总大小
        const totalSize = completedChunks.reduce((sum, chunk) => sum + chunk.uploadResult.size, 0);

        // 使用multipart info中的finalFileId更新metadata
        const finalFileId = multipartInfo.key;
        metadata.Channel = "CloudflareR2";
        // 从 R2 设置中获取渠道名称（优先使用指定的渠道名称）
        const r2Settings = context.uploadConfig.cfr2;
        let r2ChannelName = "R2_env";
        if (specifiedChannelName) {
            const r2Channel = r2Settings.channels?.find(ch => ch.name === specifiedChannelName);
            if (r2Channel) {
                r2ChannelName = r2Channel.name;
            }
        } else if (r2Settings.channels?.[0]?.name) {
            r2ChannelName = r2Settings.channels[0].name;
        }
        metadata.ChannelName = r2ChannelName;
        metadata.FileSize = (totalSize / 1024 / 1024).toFixed(2);
        metadata.FileSizeBytes = totalSize;

        // 清理multipart info
        await db.delete(multipartKey);

        // 写入数据库
        await db.put(finalFileId, "", { metadata });

        // 结束上传
        waitUntil(endUpload(context, finalFileId, metadata));

        // 更新返回链接
        const returnFormat = url.searchParams.get('returnFormat') || 'default';
        let updatedReturnLink = '';
        if (returnFormat === 'full') {
            updatedReturnLink = `${url.origin}/file/${finalFileId}`;
        } else {
            updatedReturnLink = `/file/${finalFileId}`;
        }

        return {
            success: true,
            result: [{ 'src': updatedReturnLink }]
        };

    } catch (error) {
        throw new Error(`R2 merge failed: ${error.message}`);
    }
}

// 合并S3分块信息
async function mergeS3ChunksInfo(context, uploadId, completedChunks, metadata) {
    const { env, waitUntil, uploadConfig, url, specifiedChannelName } = context;
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

        console.log(`Merging S3 chunks for uploadId: ${uploadId}, selected channel: ${s3Channel.name || 'default'}`);

        const { bucketName } = s3Channel;

        const s3Client = createS3Client(s3Channel);

        const multipartKey = `multipart_${uploadId}`;

        // 获取multipart info
        const multipartInfoData = await db.get(multipartKey);
        if (!multipartInfoData) {
            throw new Error('Multipart upload info not found');
        }

        const multipartInfo = JSON.parse(multipartInfoData);

        // 组织所有分块
        const sortedChunks = completedChunks.sort((a, b) => a.index - b.index);
        const parts = [];

        for (const chunk of sortedChunks) {
            const part = {
                ETag: chunk.uploadResult.etag,
                PartNumber: chunk.uploadResult.partNumber
            };
            parts.push(part);
        }

        // 完成multipart upload
        await s3Client.send(new CompleteMultipartUploadCommand({
            Bucket: bucketName,
            Key: multipartInfo.key,
            UploadId: multipartInfo.uploadId,
            MultipartUpload: { Parts: parts }
        }));

        // 计算总大小
        const totalSize = completedChunks.reduce((sum, chunk) => sum + chunk.uploadResult.size, 0);

        // 使用multipart info中的finalFileId更新metadata
        const finalFileId = multipartInfo.key;
        metadata.Channel = "S3";
        metadata.ChannelName = s3Channel.name;
        metadata.FileSize = (totalSize / 1024 / 1024).toFixed(2);
        metadata.FileSizeBytes = totalSize;
        metadata.S3FileKey = finalFileId;

        // 清理multipart info
        await db.delete(multipartKey);

        // 写入数据库
        await db.put(finalFileId, "", { metadata });

        // 异步结束上传
        waitUntil(endUpload(context, finalFileId, metadata));

        // 更新返回链接
        const returnFormat = url.searchParams.get('returnFormat') || 'default';
        let updatedReturnLink = '';
        if (returnFormat === 'full') {
            updatedReturnLink = `${url.origin}/file/${finalFileId}`;
        } else {
            updatedReturnLink = `/file/${finalFileId}`;
        }

        return {
            success: true,
            result: [{ src: updatedReturnLink }]
        };

    } catch (error) {
        throw new Error(`S3 merge failed: ${error.message}`);
    }
}

// 合并Telegram分块信息
async function mergeTelegramChunksInfo(context, uploadId, completedChunks, metadata) {
    const { env, waitUntil, uploadConfig, url, specifiedChannelName } = context;
    const db = getDatabase(env);

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

        console.log(`Merging Telegram chunks for uploadId: ${uploadId}, selected channel: ${tgChannel.name || 'default'}`);

        // 按顺序排列分块
        const sortedChunks = completedChunks.sort((a, b) => a.index - b.index);

        // 计算总大小
        const totalSize = sortedChunks.reduce((sum, chunk) => sum + chunk.uploadResult.size, 0);

        // 构建分块信息数组
        const chunks = sortedChunks.map(chunk => ({
            index: chunk.index,
            fileId: chunk.uploadResult.fileId,
            size: chunk.uploadResult.size,
            fileName: chunk.uploadResult.fileName
        }));

        // 生成 finalFileId
        const finalFileId = await buildUniqueFileId(context, metadata.FileName, metadata.FileType);

        // P0-9：写库前校验占位仍属于本次上传；占位过期（极少见）时报错，
        // 由调用方重试合并重新生成 ID，不直接覆盖。
        if (!(await isFileIdReserved(db, finalFileId))) {
            throw new Error('File ID reservation expired, please retry merge');
        }

        // 更新metadata
        metadata.Channel = "TelegramNew";
        metadata.ChannelName = tgChannel.name;
        metadata.IsChunked = true;
        metadata.TotalChunks = completedChunks.length;
        metadata.FileSize = (totalSize / 1024 / 1024).toFixed(2);
        metadata.FileSizeBytes = totalSize;

        // 将分片信息存储到value中
        const chunksData = JSON.stringify(chunks);

        // 写入数据库
        await db.put(finalFileId, chunksData, { metadata });

        // 异步结束上传
        waitUntil(endUpload(context, finalFileId, metadata));

        // 生成返回链接
        const returnFormat = url.searchParams.get('returnFormat') || 'default';
        let updatedReturnLink = '';
        if (returnFormat === 'full') {
            updatedReturnLink = `${url.origin}/file/${finalFileId}`;
        } else {
            updatedReturnLink = `/file/${finalFileId}`;
        }

        return {
            success: true,
            result: [{ 'src': updatedReturnLink }]
        };

    } catch (error) {
        throw new Error(`Telegram merge failed: ${error.message}`);
    }
}

// 合并Discord分块信息
async function mergeDiscordChunksInfo(context, uploadId, completedChunks, metadata) {
    const { env, waitUntil, uploadConfig, url, specifiedChannelName } = context;
    const db = getDatabase(env);

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

        console.log(`Merging Discord chunks for uploadId: ${uploadId}, selected channel: ${discordChannel.name || 'default'}`);

        // 按顺序排列分块
        const sortedChunks = completedChunks.sort((a, b) => a.index - b.index);

        // 计算总大小
        const totalSize = sortedChunks.reduce((sum, chunk) => sum + chunk.uploadResult.size, 0);

        // 构建分块信息数组（不存储 url 因为会过期，读取时通过 API 获取）
        const chunks = sortedChunks.map(chunk => ({
            index: chunk.index,
            messageId: chunk.uploadResult.messageId,
            // 注意：不存储 attachmentId 和 url，它们会在约24小时后过期
            size: chunk.uploadResult.size,
            fileName: chunk.uploadResult.fileName
        }));

        // 生成 finalFileId
        const finalFileId = await buildUniqueFileId(context, metadata.FileName, metadata.FileType);

        // P0-9：写库前校验占位仍属于本次上传；占位过期（极少见）时报错，
        // 由调用方重试合并重新生成 ID，不直接覆盖。
        if (!(await isFileIdReserved(db, finalFileId))) {
            throw new Error('File ID reservation expired, please retry merge');
        }

        // 更新metadata
        metadata.Channel = "Discord";
        metadata.ChannelName = discordChannel.name;
        metadata.IsChunked = true;
        metadata.TotalChunks = completedChunks.length;
        metadata.FileSize = (totalSize / 1024 / 1024).toFixed(2);
        metadata.FileSizeBytes = totalSize;

        // 将分片信息存储到value中
        const chunksData = JSON.stringify(chunks);

        // 写入数据库
        await db.put(finalFileId, chunksData, { metadata });

        // 异步结束上传
        waitUntil(endUpload(context, finalFileId, metadata));

        // 生成返回链接
        const returnFormat = url.searchParams.get('returnFormat') || 'default';
        let updatedReturnLink = '';
        if (returnFormat === 'full') {
            updatedReturnLink = `${url.origin}/file/${finalFileId}`;
        } else {
            updatedReturnLink = `/file/${finalFileId}`;
        }

        return {
            success: true,
            result: [{ 'src': updatedReturnLink }]
        };

    } catch (error) {
        throw new Error(`Discord merge failed: ${error.message}`);
    }
}
