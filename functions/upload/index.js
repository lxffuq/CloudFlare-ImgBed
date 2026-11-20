import { createS3Client } from '../utils/storage/s3Client.js';
import { userAuthCheck, UnauthorizedResponse } from "../utils/auth/userAuth";
import { fetchUploadConfig, fetchSecurityConfig, fetchPageConfig } from "../utils/sysConfig";
import {
    createResponse, createUploadResponse, checkUploadFormat, getUploadIp, getIPAddress, resolveFileExt,
    moderateContent, purgeCDNCache, isBlockedUploadIp, buildUniqueFileId, endUpload, getImageDimensions,
    sanitizeUploadFolder
} from "./uploadTools";
import { getFileTypeCategory, normalizeMimeType, resolveFileType } from "../utils/mimeTypes.js";
import { initializeChunkedUpload, handleChunkUpload, uploadLargeFileToTelegram, handleCleanupRequest } from "./chunkUpload";
import { handleChunkMerge } from "./chunkMerge";
import { TelegramAPI } from "../utils/storage/telegramAPI";
import { DiscordAPI } from "../utils/storage/discordAPI";
import { HuggingFaceAPI } from "../utils/storage/huggingfaceAPI";
import { WebDAVAPI } from "../utils/storage/webdavAPI";
import { PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { getDatabase } from '../utils/databaseAdapter.js';
import { resolveUploadExpiry } from '../utils/fileExpiryService.js';
import { validateExternalUrl } from '../utils/ssrfGuard.js';


export async function onRequest(context) {  // Contents of context object
    const { request, env, params, waitUntil, next, data } = context;

    // 解析请求的URL，存入 context
    const url = new URL(request.url);
    context.url = url;

    // 读取各项配置，存入 context；两处配置读取互不依赖，并行发起
    const [securityConfig, uploadConfig] = await Promise.all([
        fetchSecurityConfig(env),
        fetchUploadConfig(env, context),
    ]);

    context.securityConfig = securityConfig;
    context.uploadConfig = uploadConfig;

    // 鉴权
    const requiredPermission = 'upload';
    if (!await userAuthCheck(env, url, request, requiredPermission)) {
        return UnauthorizedResponse('Unauthorized');
    }

    // 获得上传IP
    const uploadIp = getUploadIp(request);
    // 判断上传ip是否被封禁
    const isBlockedIp = await isBlockedUploadIp(env, uploadIp);
    if (isBlockedIp) {
        return createResponse('Error: Your IP is blocked', { status: 403 });
    }

    // 检查是否为清理请求
    const cleanupRequest = url.searchParams.get('cleanup') === 'true';
    if (cleanupRequest) {
        const uploadId = url.searchParams.get('uploadId');
        const totalChunks = parseInt(url.searchParams.get('totalChunks')) || 0;
        return await handleCleanupRequest(context, uploadId, totalChunks);
    }

    // 检查是否为初始化分块上传请求
    const initChunked = url.searchParams.get('initChunked') === 'true';
    if (initChunked) {
        // 分块上传在开始前校验有效期参数，避免传完所有分块才在合并时被拒绝
        const expiry = await resolveUploadExpiry(context);
        if (expiry.error) {
            return createResponse(expiry.error, { status: 400 });
        }
        return await initializeChunkedUpload(context);
    }

    // 检查是否为分块上传
    const isChunked = url.searchParams.get('chunked') === 'true';
    const isMerge = url.searchParams.get('merge') === 'true';

    if (isChunked) {
        if (isMerge) {
            return await handleChunkMerge(context);
        } else {
            return await handleChunkUpload(context);
        }
    }

    // 处理非分块文件上传
    return await processFileUpload(context);
}


// 通用文件上传处理函数
async function processFileUpload(context, formdata = null) {
    const { request, url } = context;

    // 解析表单数据
    formdata = formdata || await request.formData();

    // 将 formdata 存储在 context 中
    context.formdata = formdata;

    // 获得上传渠道类型
    const urlParamUploadChannel = url.searchParams.get('uploadChannel');
    // 获得指定的渠道名称（可选）
    const urlParamChannelName = url.searchParams.get('channelName');

    // 获取IP地址
    const uploadIp = getUploadIp(request);
    const ipAddress = await getIPAddress(context.env, uploadIp, context.securityConfig);

    // 获取上传文件夹路径
    let uploadFolder = url.searchParams.get('uploadFolder') || '';

    // 路径安全性处理：防止路径穿越和特殊字符注入
    uploadFolder = sanitizeUploadFolder(uploadFolder);

    let uploadChannel = 'TelegramNew';
    switch (urlParamUploadChannel) {
        case 'telegram':
            uploadChannel = 'TelegramNew';
            break;
        case 'cfr2':
            uploadChannel = 'CloudflareR2';
            break;
        case 's3':
            uploadChannel = 'S3';
            break;
        case 'discord':
            uploadChannel = 'Discord';
            break;
        case 'huggingface':
            uploadChannel = 'HuggingFace';
            break;
        case 'webdav':
            uploadChannel = 'WebDAV';
            break;
        case 'external':
            uploadChannel = 'External';
            break;
        default:
            uploadChannel = 'TelegramNew';
            break;
    }

    // 将指定的渠道名称存入 context，供后续上传函数使用
    context.specifiedChannelName = urlParamChannelName || null;

    // 获取文件信息
    const time = new Date().getTime();
    const file = formdata.get('file');
    // P1-39：取到 file 后立即判空并校验是 File/Blob，缺字段返回 400 而不是
    // 在 file.name 上抛 TypeError 变成 500。
    if (!file || typeof file !== 'object' || typeof file.arrayBuffer !== 'function' || typeof file.name !== 'string') {
        return createResponse('Error: No file provided', { status: 400 });
    }
    // P1-44：空文件与超大文件在入口就拒绝。单文件上传走 Worker 请求体，
    // 上限取 Worker 请求体限制 100MB；Telegram Bot API 本身只收 50MB，
    // 单独再收紧。S3 流式上传改动风险大，本轮先做大小校验（见汇报）。
    const SINGLE_UPLOAD_MAX_BYTES = 100 * 1024 * 1024;
    const channelMaxBytes = uploadChannel === 'TelegramNew' ? 50 * 1024 * 1024 : SINGLE_UPLOAD_MAX_BYTES;
    if (file.size === 0) {
        return createResponse('Error: Empty file', { status: 400 });
    }
    if (file.size > channelMaxBytes) {
        return createResponse(`Error: File size exceeds single-upload limit (${Math.floor(channelMaxBytes / 1024 / 1024)}MB), please use chunked upload`, { status: 413 });
    }
    let fileName = file.name;
    const formatError = checkUploadFormat(fileName, context.uploadConfig);
    if (formatError) return formatError;
    // 部分客户端（同步工具、脚本）不提供有效的 Content-Type，按扩展名兜底推断。
    // 否则图片会被记成 application/octet-stream，导致随机图类型过滤、尺寸提取、
    // 图片处理校验全部失效。
    const fileType = resolveFileType(fileName, file.type);
    const fileSizeBytes = file.size; // 文件大小，单位字节
    const fileSize = (fileSizeBytes / 1024 / 1024).toFixed(2); // 文件大小，单位MB

    // 检查fileType和fileName是否存在
    if (fileType === null || fileType === undefined || fileName === null || fileName === undefined) {
        return createResponse('Error: fileType or fileName is wrong, check the integrity of this file!', { status: 400 });
    }

    // 提取图片尺寸
    let imageDimensions = null;
    if (getFileTypeCategory(fileType) === 'image') {
        try {
            // 统一读取 64KB，足以覆盖 JPEG 的 EXIF 数据和其他格式
            const headerBuffer = await file.slice(0, 65536).arrayBuffer();
            imageDimensions = getImageDimensions(headerBuffer, fileType);
        } catch (error) {
            console.error('Error reading image dimensions:', error);
        }
    }

    // 如果上传文件夹路径为空，尝试从文件名中获取
    if (uploadFolder === '' || uploadFolder === null || uploadFolder === undefined) {
        uploadFolder = fileName.split('/').slice(0, -1).join('/');
        // 对从文件名中提取的路径也进行安全处理
        uploadFolder = sanitizeUploadFolder(uploadFolder);
        // 从文件名中去除路径信息，只保留文件名部分
        fileName = fileName.split('/').pop();
    }
    // uploadFolder 已经过 sanitizeUploadFolder 处理，直接使用
    const normalizedFolder = uploadFolder;

    const metadata = {
        FileName: fileName,
        FileType: fileType,
        FileSize: fileSize,
        FileSizeBytes: fileSizeBytes,
        UploadIP: uploadIp,
        UploadAddress: ipAddress,
        ListType: "None",
        TimeStamp: time,
        Label: "None",
        Directory: normalizedFolder === '' ? '' : normalizedFolder + '/',
        Tags: []
    };

    // 添加图片尺寸信息
    if (imageDimensions) {
        metadata.Width = imageDimensions.width;
        metadata.Height = imageDimensions.height;
    }

    // 文件有效期由后端按设置决定
    const expiry = await resolveUploadExpiry(context);
    if (expiry.error) {
        return createResponse(expiry.error, { status: 400 });
    }
    if (expiry.expiresAt) {
        metadata.ExpiresAt = expiry.expiresAt;
        context.fileExpiresAt = expiry.expiresAt;
    }

    const fileExt = resolveFileExt(fileName, fileType);

    // 构建文件ID
    const fullId = await buildUniqueFileId(context, fileName, fileType);

    // 获得返回链接格式, default为返回/file/id, full为返回完整链接
    const returnFormat = url.searchParams.get('returnFormat') || 'default';
    let returnLink = '';
    if (returnFormat === 'full') {
        returnLink = `${url.origin}/file/${fullId}`;
    } else {
        returnLink = `/file/${fullId}`;
    }

    // 构建公开访问链接（使用 urlPrefix 配置）
    const pageConfig = await fetchPageConfig(context.env);
    const urlPrefixConfig = pageConfig.config?.find(c => c.id === 'urlPrefix');
    const urlPrefix = urlPrefixConfig?.value || '';
    context.publicUrl = urlPrefix ? `${urlPrefix.replace(/\/+$/, '')}/${fullId}` : '';

    /* ====================================不同渠道上传======================================= */
    // 出错是否切换渠道自动重试，默认开启
    const autoRetry = url.searchParams.get('autoRetry') === 'false' ? false : true;

    let err = '';
    // 上传到不同渠道
    if (uploadChannel === 'CloudflareR2') {
        // -------------CloudFlare R2 渠道---------------
        const res = await uploadFileToCloudflareR2(context, fullId, metadata, returnLink);
        if (res.status === 200 || !autoRetry) {
            return res;
        } else {
            err = await res.text();
        }
    } else if (uploadChannel === 'S3') {
        // ---------------------S3 渠道------------------
        const res = await uploadFileToS3(context, fullId, metadata, returnLink);
        if (res.status === 200 || !autoRetry) {
            return res;
        } else {
            err = await res.text();
        }
    } else if (uploadChannel === 'Discord') {
        // ---------------------Discord 渠道------------------
        const res = await uploadFileToDiscord(context, fullId, metadata, returnLink);
        if (res.status === 200 || !autoRetry) {
            return res;
        } else {
            err = await res.text();
        }
    } else if (uploadChannel === 'HuggingFace') {
        // ---------------------HuggingFace 渠道------------------
        const res = await uploadFileToHuggingFace(context, fullId, metadata, returnLink);
        if (res.status === 200 || !autoRetry) {
            return res;
        } else {
            err = await res.text();
        }
    } else if (uploadChannel === 'WebDAV') {
        // ---------------------WebDAV 渠道------------------
        const res = await uploadFileToWebDAV(context, fullId, metadata, returnLink);
        if (res.status === 200 || !autoRetry) {
            return res;
        } else {
            err = await res.text();
        }
    } else if (uploadChannel === 'External') {
        // --------------------外链渠道----------------------
        const res = await uploadFileToExternal(context, fullId, metadata, returnLink);
        return res;
    } else {
        // ----------------Telegram New 渠道-------------------
        const res = await uploadFileToTelegram(context, fullId, metadata, fileExt, fileName, fileType, returnLink);
        if (res.status === 200 || !autoRetry) {
            return res;
        } else {
            err = await res.text();
        }
    }

    // 上传失败，开始自动切换渠道重试
    const res = await tryRetry(err, context, uploadChannel, fullId, metadata, fileExt, fileName, fileType, returnLink);
    return res;
}

// 构建上传成功响应，自动附带 publicUrl（如果已配置）
function buildUploadResponse(context, returnLink) {
    const result = { src: returnLink };
    if (context.publicUrl) {
        result.publicUrl = context.publicUrl;
    }
    if (context.fileExpiresAt) {
        result.expiresAt = context.fileExpiresAt;
    }
    return createUploadResponse(context, [result]);
}

// P1-40/41：写库失败后尽力删掉已落盘的 S3 孤儿对象；删失败也不改变原错误
async function deleteS3ObjectBestEffort(s3Client, bucketName, key) {
    try {
        await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName, Key: key }));
    } catch (error) {
        console.warn(`Failed to delete orphan S3 object ${key}:`, error.message);
    }
}

// P1-42：尽力删除刚发到 Telegram 的消息（文件信息解析失败时防孤儿消息）
async function deleteTelegramMessageBestEffort(telegramAPI, chatId, messageId) {
    if (!messageId || !telegramAPI?.baseURL) return;
    try {
        await fetch(`${telegramAPI.baseURL}/deleteMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, message_id: messageId }),
        });
    } catch (error) {
        console.warn('Failed to delete Telegram message:', error.message);
    }
}

// 上传到Cloudflare R2
async function uploadFileToCloudflareR2(context, fullId, metadata, returnLink) {
    const { env, waitUntil, uploadConfig, formdata, specifiedChannelName } = context;
    const db = getDatabase(env);

    // 检查R2数据库是否配置
    if (typeof env.img_r2 == "undefined" || env.img_r2 == null || env.img_r2 == "") {
        return createResponse('Error: Please configure R2 database', { status: 500 });
    }

    // 检查 R2 渠道是否启用
    const r2Settings = uploadConfig.cfr2;
    if (!r2Settings.channels || r2Settings.channels.length === 0) {
        return createResponse('Error: No R2 channel provided', { status: 400 });
    }

    // 选择渠道：优先使用指定的渠道名称
    let r2Channel;
    if (specifiedChannelName) {
        r2Channel = r2Settings.channels.find(ch => ch.name === specifiedChannelName);
    }
    if (!r2Channel) {
        r2Channel = r2Settings.channels[0];
    }

    const R2DataBase = env.img_r2;

    // P1-40：R2 put 抛异常不再直接外抛（以前会绕过自动重试直接 500），
    // 改为返回 500 Response，让 tryRetry 接手换渠道。
    try {
        await R2DataBase.put(fullId, formdata.get('file'), {
            httpMetadata: { contentType: metadata.FileType },
        });
    } catch (error) {
        return createResponse(`Error: Failed to upload to R2 - ${error.message}`, { status: 500 });
    }

    // 更新metadata
    metadata.Channel = "CloudflareR2";
    metadata.ChannelName = r2Channel.name || "R2_env";

    // 图像审查，采用R2的publicUrl
    const R2PublicUrl = r2Channel.publicUrl;
    let moderateUrl = `${R2PublicUrl}/${fullId}`;
    metadata.Label = await moderateContent(env, moderateUrl);

    // 写入数据库
    try {
        await db.put(fullId, "", {
            metadata: metadata,
        });
    } catch (error) {
        // P1-40：R2 对象已落盘、写库失败时尽力删掉孤儿对象再报 500
        await R2DataBase.delete(fullId).catch(() => {});
        return createResponse('Error: Failed to write to database', { status: 500 });
    }

    // 结束上传
    waitUntil(endUpload(context, fullId, metadata));

    // 成功上传，将文件ID返回给客户端
    return buildUploadResponse(context, returnLink);
}


// 上传到 S3（支持自定义端点）
async function uploadFileToS3(context, fullId, metadata, returnLink) {
    const { env, waitUntil, uploadConfig, securityConfig, url, formdata, specifiedChannelName } = context;
    const db = getDatabase(env);

    const uploadModerate = securityConfig.upload.moderate;

    const s3Settings = uploadConfig.s3;
    const s3Channels = s3Settings.channels;
    
    // 选择渠道：优先使用指定的渠道名称
    let s3Channel;
    if (specifiedChannelName) {
        s3Channel = s3Channels.find(ch => ch.name === specifiedChannelName);
    }
    if (!s3Channel) {
        s3Channel = s3Settings.loadBalance.enabled
            ? s3Channels[Math.floor(Math.random() * s3Channels.length)]
            : s3Channels[0];
    }

    if (!s3Channel) {
        return createResponse('Error: No S3 channel provided', { status: 400 });
    }

    const { bucketName } = s3Channel;

    // 创建 S3 客户端
    const s3Client = createS3Client(s3Channel);

    // 获取文件
    const file = formdata.get("file");
    if (!file) return createResponse("Error: No file provided", { status: 400 });

    // 转换 Blob 为 Uint8Array
    const arrayBuffer = await file.arrayBuffer();
    const uint8Array = new Uint8Array(arrayBuffer);

    const s3FileName = fullId;

    try {
        // S3 上传参数
        const putObjectParams = {
            Bucket: bucketName,
            Key: s3FileName,
            Body: uint8Array, // 直接使用 Blob
            ContentType: metadata.FileType
        };

        // 执行上传
        await s3Client.send(new PutObjectCommand(putObjectParams));

        // 更新 metadata
        metadata.Channel = "S3";
        metadata.ChannelName = s3Channel.name;
        metadata.S3FileKey = s3FileName;

        // 图像审查
        if (uploadModerate && uploadModerate.enabled) {
            try {
                await db.put(fullId, "", { metadata });
            } catch {
                // P1-41：第一次写库失败时 S3 对象还没产生可访问记录，直接报 500
                await deleteS3ObjectBestEffort(s3Client, bucketName, s3FileName);
                return createResponse("Error: Failed to write to KV database", { status: 500 });
            }

            const moderateUrl = `https://${url.hostname}/file/${fullId}`;
            await purgeCDNCache(env, moderateUrl, url);
            metadata.Label = await moderateContent(env, moderateUrl);
        }

        // 写入数据库
        try {
            await db.put(fullId, "", { metadata });
        } catch {
            // P1-41：第二次写库失败时回滚删除第一次的记录，并尽力删 S3 孤儿对象，
            // 不再出现“报失败但文件能访问”
            await db.delete(fullId).catch(() => {});
            await deleteS3ObjectBestEffort(s3Client, bucketName, s3FileName);
            return createResponse("Error: Failed to write to database", { status: 500 });
        }

        // 结束上传
        waitUntil(endUpload(context, fullId, metadata));

        return buildUploadResponse(context, returnLink);
    } catch (error) {
        return createResponse(`Error: Failed to upload to S3 - ${error.message}`, { status: 500 });
    }
}


// 上传到Telegram
async function uploadFileToTelegram(context, fullId, metadata, fileExt, fileName, fileType, returnLink) {
    const { env, waitUntil, uploadConfig, url, formdata, specifiedChannelName } = context;
    const db = getDatabase(env);

    // 选择一个 Telegram 渠道上传
    const tgSettings = uploadConfig.telegram;
    const tgChannels = tgSettings.channels;
    
    let tgChannel;
    // 如果指定了渠道名称，优先使用指定的渠道
    if (specifiedChannelName) {
        tgChannel = tgChannels.find(ch => ch.name === specifiedChannelName);
    }
    // 未指定或未找到指定渠道，使用负载均衡或第一个
    if (!tgChannel) {
        tgChannel = tgSettings.loadBalance.enabled ? tgChannels[Math.floor(Math.random() * tgChannels.length)] : tgChannels[0];
    }
    if (!tgChannel) {
        return createResponse('Error: No Telegram channel provided', { status: 400 });
    }

    const tgBotToken = tgChannel.botToken;
    const tgChatId = tgChannel.chatId;
    const tgProxyUrl = tgChannel.proxyUrl || '';
    const file = formdata.get('file');
    const fileSize = file.size;

    const telegramAPI = new TelegramAPI(tgBotToken, tgProxyUrl);

    // 16MB 分片阈值 (TG Bot getFile download limit: 20MB, leave 4MB safety margin)
    const CHUNK_SIZE = 16 * 1024 * 1024; // 16MB

    if (fileSize > CHUNK_SIZE) {
        // 大文件分片上传
        return await uploadLargeFileToTelegram(context, file, fullId, metadata, fileName, fileType, returnLink, tgBotToken, tgChatId, tgChannel);
    }

    // 由于TG会把gif后缀的文件转为视频，所以需要修改后缀名绕过限制
    if (fileExt === 'gif') {
        const newFileName = fileName.replace(/\.gif$/i, '.jpeg');
        const newFile = new File([formdata.get('file')], newFileName, { type: fileType });
        formdata.set('file', newFile);
    } else if (fileExt === 'webp') {
        const newFileName = fileName.replace(/\.webp$/i, '.jpeg');
        const newFile = new File([formdata.get('file')], newFileName, { type: fileType });
        formdata.set('file', newFile);
    }

    // 选择对应的发送接口
    const fileTypeMap = {
        'image/': { 'url': 'sendPhoto', 'type': 'photo' },
        'video/': { 'url': 'sendVideo', 'type': 'video' },
        'audio/': { 'url': 'sendAudio', 'type': 'audio' },
        'application/pdf': { 'url': 'sendDocument', 'type': 'document' },
    };

    const defaultType = { 'url': 'sendDocument', 'type': 'document' };

    const mimeType = normalizeMimeType(fileType);
    const sendType = Object.keys(fileTypeMap).find(key => mimeType.startsWith(key));
    let sendFunction = sendType ? fileTypeMap[sendType] : defaultType;

    // GIF ICO 等发送接口特殊处理
    if (mimeType === 'image/gif' || mimeType === 'image/webp' || fileExt === 'gif' || fileExt === 'webp') {
        sendFunction = { 'url': 'sendAnimation', 'type': 'animation' };
    } else if (mimeType === 'image/svg+xml' || mimeType === 'image/x-icon') {
        sendFunction = { 'url': 'sendDocument', 'type': 'document' };
    }

    // 根据服务端压缩设置处理接口：从参数中获取serverCompress，如果为false，则使用sendDocument接口
    if (url.searchParams.get('serverCompress') === 'false') {
        sendFunction = { 'url': 'sendDocument', 'type': 'document' };
    }

    // 上传文件到 Telegram
    let res = createResponse('upload error, check your environment params about telegram channel!', { status: 400 });
    try {
        const response = await telegramAPI.sendFile(formdata.get('file'), tgChatId, sendFunction.url, sendFunction.type);
        // P1-42：getFileInfo 返回 null 未判空会抛 TypeError，被外层改写成
        // 400（文件其实已发出）。空值时记明确日志、返回 502，并尽力删
        // 掉刚发的 TG 消息防孤儿。animation 等类型的解析分支在
        // telegramAPI.js（不在本组文件集合内），未改，见汇报。
        const fileInfo = telegramAPI.getFileInfo(response);
        if (!fileInfo || !fileInfo.file_id) {
            console.error('Telegram upload error: getFileInfo returned null');
            await deleteTelegramMessageBestEffort(telegramAPI, tgChatId, response?.result?.message_id);
            return createResponse('Error: Failed to get file info from Telegram', { status: 502 });
        }
        const filePath = await telegramAPI.getFilePath(fileInfo.file_id);
        if (!filePath) {
            console.error('Telegram upload error: getFilePath returned null');
            await deleteTelegramMessageBestEffort(telegramAPI, tgChatId, response?.result?.message_id);
            return createResponse('Error: Failed to get file path from Telegram', { status: 502 });
        }
        const id = fileInfo.file_id;
        // 更新FileSize
        metadata.FileSize = (fileInfo.file_size / 1024 / 1024).toFixed(2);

        // 更新metadata
        metadata.Channel = "TelegramNew";
        metadata.ChannelName = tgChannel.name;
        metadata.TgFileId = id;

        // P0-11/P1-41：先写一条 Label:"pending" 的临时记录（不进索引，
        // endUpload 只在最终写库成功后才调），审查改用自有域名地址
        // /file/<id>，不再把带 Bot Token 的 TG 直链发给第三方审查服务。
        // 最终写库失败时回滚删除临时记录，不再“报失败但文件能访问”。
        try {
            await db.put(fullId, "", { metadata: { ...metadata, Label: "pending" } });
        } catch (error) {
            return createResponse('Error: Failed to write to KV database', { status: 500 });
        }
        const moderateUrl = `https://${url.hostname}/file/${fullId}`;
        await purgeCDNCache(env, moderateUrl, url);
        metadata.Label = await moderateContent(env, moderateUrl);

        // 写入最终记录
        try {
            await db.put(fullId, "", {
                metadata: metadata,
            });
        } catch (error) {
            await db.delete(fullId).catch(() => {});
            return createResponse('Error: Failed to write to KV database', { status: 500 });
        }

        // 结束上传
        waitUntil(endUpload(context, fullId, metadata));

        // 将响应返回给客户端
        res = buildUploadResponse(context, returnLink);

    } catch (error) {
        console.log('Telegram upload error:', error.message);
        res = createResponse('upload error, check your environment params about telegram channel!', { status: 400 });
    } finally {
        return res;
    }
}


// 外链渠道
async function uploadFileToExternal(context, fullId, metadata, returnLink) {
    const { env, waitUntil, formdata } = context;
    const db = getDatabase(env);

    // 直接将外链写入metadata
    metadata.Channel = "External";
    metadata.ChannelName = "External";
    // 从 formdata 中获取外链
    const extUrl = formdata.get('url');
    if (extUrl === null || extUrl === undefined) {
        return createResponse('Error: No url provided', { status: 400 });
    }
    // P1-30：外链只允许 http(s) 且拒绝内网/保留地址，否则可作 SSRF 跳板
    const extUrlCheck = validateExternalUrl(extUrl);
    if (!extUrlCheck.ok) {
        return createResponse(`Error: ${extUrlCheck.error}`, { status: 400 });
    }
    metadata.ExternalLink = extUrl;
    // 写入KV数据库
    try {
        await db.put(fullId, "", {
            metadata: metadata,
        });
    } catch (error) {
        return createResponse('Error: Failed to write to KV database', { status: 500 });
    }

    // 结束上传
    waitUntil(endUpload(context, fullId, metadata));

    // 返回结果
    return buildUploadResponse(context, returnLink);
}


// 上传到 Discord
async function uploadFileToDiscord(context, fullId, metadata, returnLink) {
    const { env, waitUntil, uploadConfig, formdata, specifiedChannelName } = context;
    const db = getDatabase(env);

    // 获取 Discord 渠道配置
    const discordSettings = uploadConfig.discord;
    if (!discordSettings || !discordSettings.channels || discordSettings.channels.length === 0) {
        return createResponse('Error: No Discord channel configured', { status: 400 });
    }

    // 选择渠道：优先使用指定的渠道名称
    const discordChannels = discordSettings.channels;
    let discordChannel;
    if (specifiedChannelName) {
        discordChannel = discordChannels.find(ch => ch.name === specifiedChannelName);
    }
    if (!discordChannel) {
        discordChannel = discordSettings.loadBalance?.enabled
            ? discordChannels[Math.floor(Math.random() * discordChannels.length)]
            : discordChannels[0];
    }

    if (!discordChannel || !discordChannel.botToken || !discordChannel.channelId) {
        return createResponse('Error: Discord channel not properly configured', { status: 400 });
    }

    const file = formdata.get('file');
    const fileSize = file.size;
    const fileName = metadata.FileName;

    // Discord 文件大小限制：Nitro 会员 25MB，免费用户 10MB
    const isNitro = discordChannel.isNitro || false;
    const DISCORD_MAX_SIZE = isNitro ? 25 * 1024 * 1024 : 10 * 1024 * 1024;
    if (fileSize > DISCORD_MAX_SIZE) {
        const limitMB = isNitro ? 25 : 10;
        return createResponse(`Error: File size exceeds Discord limit (${limitMB}MB), please use another channel`, { status: 413 });
    }

    const discordAPI = new DiscordAPI(discordChannel.botToken);

    try {
        // 上传文件到 Discord
        const response = await discordAPI.sendFile(file, discordChannel.channelId, fileName);
        const fileInfo = discordAPI.getFileInfo(response);

        if (!fileInfo) {
            throw new Error('Failed to get file info from Discord response');
        }

        // 更新 metadata
        metadata.Channel = "Discord";
        metadata.ChannelName = discordChannel.name || "Discord_env";
        metadata.FileSize = (fileInfo.file_size / 1024 / 1024).toFixed(2);
        metadata.DiscordMessageId = fileInfo.message_id;
        // 注意：不存储 DiscordAttachmentUrl，因为 Discord 附件 URL 会在约24小时后过期
        // 读取时会通过 API 获取新的 URL

        // 图像审查（使用 Discord CDN URL 或代理 URL）
        let moderateUrl = fileInfo.url;
        if (discordChannel.proxyUrl) {
            moderateUrl = fileInfo.url.replace('https://cdn.discordapp.com', `https://${discordChannel.proxyUrl}`);
        }
        metadata.Label = await moderateContent(env, moderateUrl);

        // 写入 KV 数据库
        try {
            await db.put(fullId, "", { metadata });
        } catch (error) {
            return createResponse('Error: Failed to write to KV database', { status: 500 });
        }

        // 结束上传
        waitUntil(endUpload(context, fullId, metadata));

        // 返回成功响应
        return buildUploadResponse(context, returnLink);

    } catch (error) {
        console.error('Discord upload error:', error.message);
        return createResponse(`Error: Discord upload failed - ${error.message}`, { status: 500 });
    }
}


// 上传到 HuggingFace
async function uploadFileToHuggingFace(context, fullId, metadata, returnLink) {
    const { env, waitUntil, uploadConfig, formdata, specifiedChannelName } = context;
    const db = getDatabase(env);

    console.log('=== HuggingFace Upload Start ===');

    // 获取 HuggingFace 渠道配置
    const hfSettings = uploadConfig.huggingface;
    console.log('HuggingFace settings:', hfSettings ? 'found' : 'not found');

    if (!hfSettings || !hfSettings.channels || hfSettings.channels.length === 0) {
        console.log('Error: No HuggingFace channel configured');
        return createResponse('Error: No HuggingFace channel configured', { status: 400 });
    }

    // 选择渠道：优先使用指定的渠道名称
    const hfChannels = hfSettings.channels;
    console.log('HuggingFace channels count:', hfChannels.length);

    let hfChannel;
    if (specifiedChannelName) {
        hfChannel = hfChannels.find(ch => ch.name === specifiedChannelName);
    }
    if (!hfChannel) {
        hfChannel = hfSettings.loadBalance?.enabled
            ? hfChannels[Math.floor(Math.random() * hfChannels.length)]
            : hfChannels[0];
    }

    console.log('Selected channel:', hfChannel?.name, 'repo:', hfChannel?.repo);

    if (!hfChannel || !hfChannel.token || !hfChannel.repo) {
        console.log('Error: HuggingFace channel not properly configured', {
            hasChannel: !!hfChannel,
            hasToken: !!hfChannel?.token,
            hasRepo: !!hfChannel?.repo
        });
        return createResponse('Error: HuggingFace channel not properly configured', { status: 400 });
    }

    const file = formdata.get('file');
    const fileName = metadata.FileName;
    // 获取前端预计算的 SHA256（如果有）
    const precomputedSha256 = formdata.get('sha256') || null;
    console.log('File to upload:', fileName, 'size:', file?.size, 'precomputed SHA256:', precomputedSha256 ? 'yes' : 'no');

    // 生成唯一标识符前缀（UUID格式），加在文件名前面
    const uniquePrefix = crypto.randomUUID();
    const lastSlashIndex = fullId.lastIndexOf('/');
    const hfFilePath = lastSlashIndex === -1 
        ? `${uniquePrefix}_${fullId}` 
        : `${fullId.substring(0, lastSlashIndex + 1)}${uniquePrefix}_${fullId.substring(lastSlashIndex + 1)}`;
    console.log('HuggingFace file path:', hfFilePath);

    const huggingfaceAPI = new HuggingFaceAPI(hfChannel.token, hfChannel.repo, hfChannel.isPrivate || false);

    try {
        // 上传文件到 HuggingFace（传入预计算的 SHA256）
        console.log('Starting HuggingFace upload...');
        const result = await huggingfaceAPI.uploadFile(file, hfFilePath, `Upload ${fileName}`, precomputedSha256);
        console.log('HuggingFace upload result:', result);

        if (!result.success) {
            throw new Error('Failed to upload file to HuggingFace');
        }

        // 更新 metadata
        metadata.Channel = "HuggingFace";
        metadata.ChannelName = hfChannel.name || "HuggingFace_env";
        metadata.HfFilePath = hfFilePath;

        // 图像审查
        const securityConfig = context.securityConfig;
        const uploadModerate = securityConfig.upload?.moderate;
        
        if (uploadModerate && uploadModerate.enabled) {
            if (!hfChannel.isPrivate) {
                // 公开仓库：直接通过公开URL访问进行审查，只写入1次KV
                metadata.Label = await moderateContent(env, result.fileUrl);
            } else {
                // 私有仓库：先写入KV，再通过自己的域名访问进行审查
                try {
                    await db.put(fullId, "", { metadata });
                } catch (error) {
                    return createResponse('Error: Failed to write to KV database', { status: 500 });
                }
                
                const moderateUrl = `https://${context.url.hostname}/file/${fullId}`;
                await purgeCDNCache(env, moderateUrl, context.url);
                metadata.Label = await moderateContent(env, moderateUrl);
            }
        }

        // 写入 KV 数据库
        try {
            await db.put(fullId, "", { metadata });
        } catch (error) {
            // P1-41：第二次写库失败时回滚删除第一次的记录，不再“报失败但文件能访问”
            //（HF 远端文件本身删不掉，见汇报）
            await db.delete(fullId).catch(() => {});
            return createResponse('Error: Failed to write to KV database', { status: 500 });
        }

        // 结束上传
        waitUntil(endUpload(context, fullId, metadata));

        // 返回成功响应
        return buildUploadResponse(context, returnLink);

    } catch (error) {
        console.error('HuggingFace upload error:', error.message);
        return createResponse(`Error: HuggingFace upload failed - ${error.message}`, { status: 500 });
    }
}


// 上传到 WebDAV
async function uploadFileToWebDAV(context, fullId, metadata, returnLink) {
    const { env, waitUntil, uploadConfig, securityConfig, url, formdata, specifiedChannelName } = context;
    const db = getDatabase(env);

    const webdavSettings = uploadConfig.webdav;
    if (!webdavSettings || !webdavSettings.channels || webdavSettings.channels.length === 0) {
        return createResponse('Error: No WebDAV channel configured', { status: 400 });
    }

    const webdavChannels = webdavSettings.channels;
    let webdavChannel;
    if (specifiedChannelName) {
        webdavChannel = webdavChannels.find(ch => ch.name === specifiedChannelName);
    }
    if (!webdavChannel) {
        webdavChannel = webdavSettings.loadBalance?.enabled
            ? webdavChannels[Math.floor(Math.random() * webdavChannels.length)]
            : webdavChannels[0];
    }

    if (!webdavChannel || !webdavChannel.baseUrl) {
        return createResponse('Error: WebDAV channel not properly configured', { status: 400 });
    }

    const file = formdata.get('file');
    if (!file) {
        return createResponse('Error: No file provided', { status: 400 });
    }

    try {
        const webdavAPI = new WebDAVAPI(webdavChannel);
        await webdavAPI.putFile(fullId, file, metadata.FileType);

        metadata.Channel = "WebDAV";
        metadata.ChannelName = webdavChannel.name || "WebDAV_env";
        metadata.WebDAVFilePath = fullId;
        const webdavPublicUrl = webdavChannel.publicUrl
            ? webdavAPI.buildPublicUrl(fullId, webdavChannel.publicUrl)
            : '';

        const uploadModerate = securityConfig.upload?.moderate;
        if (uploadModerate && uploadModerate.enabled) {
            if (webdavPublicUrl) {
                metadata.Label = await moderateContent(env, webdavPublicUrl);
            } else {
                try {
                    await db.put(fullId, "", { metadata });
                } catch {
                    // 第一次写库失败：远端文件已传、无记录指向，尽力删掉孤儿文件
                    await webdavAPI.deleteFile(fullId).catch(() => {});
                    return createResponse('Error: Failed to write to database', { status: 500 });
                }

                const moderateUrl = `https://${url.hostname}/file/${fullId}`;
                await purgeCDNCache(env, moderateUrl, url);
                metadata.Label = await moderateContent(env, moderateUrl);
            }
        }

        try {
            await db.put(fullId, "", { metadata });
        } catch {
            // P1-41：第二次写库失败时回滚删除第一次的记录，并尽力删远端孤儿文件
            await db.delete(fullId).catch(() => {});
            await webdavAPI.deleteFile(fullId).catch(() => {});
            return createResponse('Error: Failed to write to database', { status: 500 });
        }

        waitUntil(endUpload(context, fullId, metadata));

        return buildUploadResponse(context, returnLink);
    } catch (error) {
        console.error('WebDAV upload error:', error.message);
        return createResponse(`Error: WebDAV upload failed - ${error.message}`, { status: 500 });
    }
}


// 自动切换渠道重试
async function tryRetry(err, context, uploadChannel, fullId, metadata, fileExt, fileName, fileType, returnLink) {
    const { env, url, formdata } = context;

    // P1-40：各渠道函数统一“返回 Response、不抛错”。这里再包一层 try/catch，
    // 万一某个渠道函数仍抛异常（如 R2 偶发失败），也只记一条错误、继续换
    // 下一个渠道，而不是整个重试直接 500。
    async function callChannel(channel, fn) {
        try {
            return await fn();
        } catch (error) {
            console.error(`Channel ${channel} threw during retry:`, error.message);
            return createResponse(`Error: ${channel} failed - ${error.message}`, { status: 500 });
        }
    }
    function dispatch(channel) {
        if (channel === 'CloudflareR2') {
            return uploadFileToCloudflareR2(context, fullId, metadata, returnLink);
        } else if (channel === 'TelegramNew') {
            return uploadFileToTelegram(context, fullId, metadata, fileExt, fileName, fileType, returnLink);
        } else if (channel === 'S3') {
            return uploadFileToS3(context, fullId, metadata, returnLink);
        } else if (channel === 'HuggingFace') {
            return uploadFileToHuggingFace(context, fullId, metadata, returnLink);
        } else if (channel === 'WebDAV') {
            return uploadFileToWebDAV(context, fullId, metadata, returnLink);
        } else if (channel === 'Discord') {
            return uploadFileToDiscord(context, fullId, metadata, returnLink);
        }
        return null;
    }

    // 渠道列表（Discord 因为有 10MB 限制，放在最后尝试）
    const channelList = ['CloudflareR2', 'TelegramNew', 'S3', 'HuggingFace', 'WebDAV', 'Discord'];
    const errMessages = {};
    errMessages[uploadChannel] = 'Error: ' + uploadChannel + err;

    // 先用原渠道再试一次（关闭服务端压缩）
    url.searchParams.set('serverCompress', 'false');
    let retryRes = await callChannel(uploadChannel, () => dispatch(uploadChannel));

    // 原渠道重试成功，直接返回
    if (retryRes && retryRes.status === 200) {
        return retryRes;
    } else if (retryRes) {
        errMessages[uploadChannel + '_retry'] = 'Error: ' + uploadChannel + ' retry - ' + await retryRes.text();
    }

    // 原渠道重试失败，切换到其他渠道
    for (let i = 0; i < channelList.length; i++) {
        if (channelList[i] !== uploadChannel) {
            const res = await callChannel(channelList[i], () => dispatch(channelList[i]));

            if (res && res.status === 200) {
                return res;
            } else if (res) {
                errMessages[channelList[i]] = 'Error: ' + channelList[i] + await res.text();
            }
        }
    }

    return createResponse(JSON.stringify(errMessages), { status: 500 });
}
