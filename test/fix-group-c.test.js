import assert from 'node:assert/strict';
import { File } from 'node:buffer';
import { loadFunction, memoryDatabase } from './helpers/loadFunction.js';
import * as responses from '../functions/utils/apiResponse.js';
import * as fileExpiryHelpers from '../functions/utils/fileExpiryHelpers.js';
import * as fileTools from '../functions/file/fileTools.js';
import * as imageTransform from '../functions/file/imageTransform.js';
import * as adaptive from '../functions/random/adaptive.js';
import * as ssrfGuard from '../functions/utils/ssrfGuard.js';
import { png } from './helpers/files.js';

const SHA256 = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';

describe('fix group C: upload chain and file access', () => {
    let db, tools, mocks, storage, waits;

    beforeEach(async () => {
        db = memoryDatabase();
        storage = {};
        waits = [];
        tools = await loadFunction('functions/upload/uploadTools.js', { getDatabase: () => db });
        const { UnauthorizedResponse } = await loadFunction('functions/utils/auth/userAuth.js');
        mocks = {
            ...tools,
            ...responses,
            ...ssrfGuard,
            getDatabase: () => db,
            checkDatabaseConfig: () => ({ usingD1: false }),
            fetchSecurityConfig: async () => ({ upload: { moderate: { enabled: false } }, access: { whiteListMode: false } }),
            fetchUploadConfig: async () => ({
                cfr2: { channels: [{ name: 'mock' }] },
                telegram: { channels: [{ name: 'mock', botToken: 'mock', chatId: 'mock' }], loadBalance: { enabled: false } },
                s3: { channels: [{ name: 'mock', bucketName: 'mock' }], loadBalance: { enabled: false } },
                webdav: { channels: [{ name: 'mock', baseUrl: 'https://storage.invalid' }] },
                huggingface: { channels: [{ name: 'mock', token: 'mock', repo: 'mock/repo', isPrivate: true }] },
            }),
            fetchPageConfig: async () => ({ config: [] }),
            userAuthCheck: async () => true,
            UnauthorizedResponse,
            isBlockedUploadIp: async () => false,
            getIPAddress: async () => '',
            getUploadIp: () => '',
            moderateContent: async () => 'None',
            endUpload: async () => {},
            resolveUploadExpiry: async () => ({ expiresAt: null }),
            createS3Client: () => ({ async send(command) { return { UploadId: 'multipart', ETag: 'etag' }; } }),
            PutObjectCommand: class { constructor(input) { this.kind = 'put'; this.input = input; } },
            DeleteObjectCommand: class { constructor(input) { this.kind = 'delete'; this.input = input; } },
            CreateMultipartUploadCommand: class { constructor(input) { this.kind = 'create'; this.input = input; } },
            UploadPartCommand: class { constructor(input) { this.kind = 'part'; this.input = input; } },
            CompleteMultipartUploadCommand: class { constructor(input) { this.kind = 'complete'; this.input = input; } },
            GetObjectCommand: class { constructor(input) { this.kind = 'get'; this.input = input; } },
            TelegramAPI: class {
                async sendFile(file, chat, method) { storage.method = method; storage.fileName = file.name; return {}; }
                getFileInfo() { return { file_id: 'mock-id', file_size: 24 }; }
                async getFilePath() { return 'mock-path'; }
            },
            WebDAVAPI: class { async putFile(id, file, type) { storage.contentType = type; } },
            HuggingFaceAPI: class {
                async getLfsUploadInfo() { return {}; }
                async commitLfsFile() { return {}; }
            },
        };
    });

    function context(url, body) {
        return {
            request: new Request(url, { method: 'POST', body }),
            url: new URL(url),
            env: { img_r2: {
                async put(id, file, options) { storage.contentType = options.httpMetadata.contentType; },
                async createMultipartUpload(id, options) { storage.contentType = options.httpMetadata.contentType; return { uploadId: 'multipart' }; },
                resumeMultipartUpload() { return { async uploadPart() { return { etag: 'etag' }; }, async complete() {} }; },
            } },
            waitUntil(promise) { waits.push(promise); },
            securityConfig: { upload: { moderate: { enabled: false } } },
        };
    }

    function chunkContext(url, form) {
        const ctx = context(url, form);
        ctx.uploadConfig = { cfr2: { channels: [{ name: 'mock' }] } };
        return ctx;
    }

    async function initSession({ totalChunks = 1, channel = 'cfr2', fileSize = null } = {}) {
        const chunk = await loadFunction('functions/upload/chunkUpload.js', mocks, {
            setTimeout: (...args) => setTimeout(...args).unref(),
        });
        const form = new FormData();
        form.set('originalFileName', 'photo.png');
        form.set('originalFileType', 'image/png');
        form.set('totalChunks', String(totalChunks));
        if (fileSize !== null) form.set('fileSize', String(fileSize));
        const ctx = chunkContext(`https://test/upload?uploadChannel=${channel}`, form);
        const initialized = await chunk.initializeChunkedUpload(ctx);
        assert.equal(initialized.status, 200, await initialized.clone().text());
        const { uploadId } = await initialized.json();
        return { chunk, uploadId, ctx };
    }

    it('P1-45: sanitizeFileName does not throw on a bare % in the name', () => {
        assert.equal(tools.sanitizeFileName('100%.png'), '100_.png');
        assert.equal(tools.sanitizeFileName('a%b%c.png'), 'a_b_c.png');
    });

    it('P0-9: buildUniqueFileId reserves the id so a second call cannot reuse it', async () => {
        const first = await tools.buildUniqueFileId({ env: {}, url: new URL('https://test/upload?uploadNameType=origin') }, 'photo.png', 'image/png');
        assert.equal(first, 'photo.png');
        assert.notEqual(await db.get(tools.fileIdReserveKey(first)), null);
        const second = await tools.buildUniqueFileId({ env: {}, url: new URL('https://test/upload?uploadNameType=origin') }, 'photo.png', 'image/png');
        assert.equal(second, 'photo(1).png');
    });

    it('P1-33/34: chunk init and upload reject NaN, negative, out-of-range and oversized counts', async () => {
        const chunk = await loadFunction('functions/upload/chunkUpload.js', mocks, {
            setTimeout: (...args) => setTimeout(...args).unref(),
        });
        for (const totalChunks of ['abc', '0', '-1', '1.5', '201']) {
            const form = new FormData();
            form.set('originalFileName', 'photo.png');
            form.set('totalChunks', totalChunks);
            assert.equal((await chunk.initializeChunkedUpload(chunkContext('https://test/upload?uploadChannel=cfr2', form))).status, 400, totalChunks);
        }
        const { uploadId, ctx } = await initSession({ totalChunks: 2 });
        for (const chunkIndex of ['abc', '-1', '2', '1.5']) {
            const form = new FormData();
            form.set('originalFileName', 'photo.png');
            form.set('totalChunks', '2');
            form.set('uploadId', uploadId);
            form.set('chunkIndex', chunkIndex);
            form.set('file', new File([png()], 'part'));
            ctx.request = new Request(ctx.url, { method: 'POST', body: form });
            assert.equal((await chunk.handleChunkUpload(ctx)).status, 400, chunkIndex);
        }
    });

    it('P1-32: a chunk whose storage upload fails returns 500 with its chunkIndex', async () => {
        const failingMocks = {
            ...mocks,
            createS3Client: () => { throw new Error('boom'); },
        };
        const chunk = await loadFunction('functions/upload/chunkUpload.js', failingMocks, {
            setTimeout: (...args) => setTimeout(...args).unref(),
        });
        const ctx = chunkContext('https://test/upload?uploadChannel=cfr2', new FormData());
        // R2 path: make createMultipartUpload throw instead
        ctx.env.img_r2.createMultipartUpload = async () => { throw new Error('R2 unavailable'); };
        const { uploadId } = await initSession({ totalChunks: 1 });
        const form = new FormData();
        form.set('originalFileName', 'photo.png');
        form.set('originalFileType', 'image/png');
        form.set('totalChunks', '1');
        form.set('uploadId', uploadId);
        form.set('chunkIndex', '0');
        form.set('file', new File([png()], 'part'));
        ctx.request = new Request(ctx.url, { method: 'POST', body: form });
        const response = await chunk.handleChunkUpload(ctx);
        assert.equal(response.status, 500);
        const body = await response.json();
        assert.equal(body.chunkIndex, 0);
        assert.equal(body.retryable, true);
        assert.equal((await db.getWithMetadata(`chunk_${uploadId}_000`)).metadata.status, 'failed');
    });

    it('P0-10: cleanup without a session is rejected, and a foreign IP cannot clean up', async () => {
        // 归属校验读真实的请求 IP，这里不能用 mocks 里写死的 getUploadIp 空串
        const chunk = await loadFunction('functions/upload/chunkUpload.js', { ...mocks, getUploadIp: tools.getUploadIp }, {
            setTimeout: (...args) => setTimeout(...args).unref(),
        });
        const ctx = context('https://test/upload?cleanup=true&uploadId=nope&totalChunks=1');
        assert.equal((await chunk.handleCleanupRequest(ctx, 'nope', 1)).status, 404);

        const { uploadId } = await initSession({ totalChunks: 1 });
        const session = JSON.parse(await db.get(`upload_session_${uploadId}`));
        session.uploadIp = '1.2.3.4';
        await db.put(`upload_session_${uploadId}`, JSON.stringify(session));
        await db.put(`chunk_${uploadId}_000`, 'x', { metadata: { status: 'uploading' } });
        const foreign = context('https://test/upload?cleanup=true&totalChunks=1');
        foreign.request = new Request('https://test/upload?cleanup=true&totalChunks=1', { headers: { 'cf-connecting-ip': '9.9.9.9' } });
        assert.equal((await chunk.handleCleanupRequest(foreign, uploadId, 1)).status, 403);
        assert.notEqual(await db.get(`chunk_${uploadId}_000`), null);
        const own = context('https://test/upload?cleanup=true&totalChunks=1');
        own.request = new Request('https://test/upload?cleanup=true&totalChunks=1', { headers: { 'cf-connecting-ip': '1.2.3.4' } });
        assert.equal((await chunk.handleCleanupRequest(own, uploadId, 1)).status, 200);
        assert.equal(await db.get(`chunk_${uploadId}_000`), null);
    });

    it('P1-36: merge returns 409 while a chunk is still uploading and keeps the data', async () => {
        const { chunk, uploadId, ctx } = await initSession({ totalChunks: 1 });
        await db.put(`chunk_${uploadId}_000`, 'x', { metadata: { status: 'uploading', chunkSize: 24 } });
        const merge = await loadFunction('functions/upload/chunkMerge.js', { ...mocks, ...chunk });
        const form = new FormData();
        form.set('originalFileName', 'photo.png');
        form.set('uploadId', uploadId);
        form.set('totalChunks', '1');
        ctx.request = new Request(ctx.url, { method: 'POST', body: form });
        const response = await merge.handleChunkMerge(ctx);
        assert.equal(response.status, 409);
        assert.notEqual(await db.get(`upload_session_${uploadId}`), null);
        assert.notEqual(await db.get(`chunk_${uploadId}_000`), null);
    });

    it('P1-35: merge refuses a completed chunk that lacks the channel-required field', async () => {
        const { chunk, uploadId, ctx } = await initSession({ totalChunks: 1 });
        await db.put(`chunk_${uploadId}_000`, '', { metadata: {
            status: 'completed', uploadResult: {}, chunkSize: 24, uploadChannel: 'cfr2',
        } });
        const merge = await loadFunction('functions/upload/chunkMerge.js', { ...mocks, ...chunk });
        const form = new FormData();
        form.set('originalFileName', 'photo.png');
        form.set('uploadId', uploadId);
        form.set('totalChunks', '1');
        ctx.request = new Request(ctx.url, { method: 'POST', body: form });
        const response = await merge.handleChunkMerge(ctx);
        assert.equal(response.status, 500);
        assert.match(await response.text(), /missing etag/);
        // 失败不写库、不清数据，可重试合并
        assert.notEqual(await db.get(`upload_session_${uploadId}`), null);
        assert.notEqual(await db.get(`chunk_${uploadId}_000`), null);
    });

    it('P0-12: a repeated merge returns the first result instead of merging twice', async () => {
        const { chunk, uploadId, ctx } = await initSession({ totalChunks: 1 });
        const partForm = new FormData();
        partForm.set('originalFileName', 'photo.png');
        partForm.set('originalFileType', 'image/png');
        partForm.set('totalChunks', '1');
        partForm.set('uploadId', uploadId);
        partForm.set('chunkIndex', '0');
        partForm.set('file', new File([png()], 'part'));
        ctx.request = new Request(ctx.url, { method: 'POST', body: partForm });
        assert.equal((await chunk.handleChunkUpload(ctx)).status, 200);
        const merge = await loadFunction('functions/upload/chunkMerge.js', { ...mocks, ...chunk, endUpload: async () => {} });
        const mergeForm = new FormData();
        mergeForm.set('originalFileName', 'photo.png');
        mergeForm.set('uploadId', uploadId);
        mergeForm.set('totalChunks', '1');
        ctx.request = new Request(ctx.url, { method: 'POST', body: mergeForm });
        const first = await merge.handleChunkMerge(ctx);
        assert.equal(first.status, 200, await first.clone().text());
        const firstBody = await first.json();
        ctx.request = new Request(ctx.url, { method: 'POST', body: mergeForm });
        const second = await merge.handleChunkMerge(ctx);
        assert.equal(second.status, 200);
        assert.deepEqual(await second.json(), firstBody);
    });

    it('P1-39/44: single upload without a file, or with an empty file, returns 400', async () => {
        const route = await loadFunction('functions/upload/index.js', mocks);
        assert.equal((await route.onRequest(context('https://test/upload?uploadChannel=cfr2', new FormData()))).status, 400);
        const empty = new FormData();
        empty.set('file', new File([], 'empty.png', { type: 'image/png' }));
        assert.equal((await route.onRequest(context('https://test/upload?uploadChannel=cfr2', empty))).status, 400);
    });

    it('P1-30: external uploads reject internal addresses and accept public https URLs', async () => {
        const route = await loadFunction('functions/upload/index.js', mocks);
        for (const url of ['http://169.254.169.254/latest/meta-data/', 'http://localhost./admin', 'ftp://example.com/x.png', 'http://10.0.0.5/x.png']) {
            const form = new FormData();
            form.set('file', new File([png()], 'photo.png', { type: 'image/png' }));
            form.set('url', url);
            const response = await route.onRequest(context('https://test/upload?uploadChannel=external', form));
            assert.equal(response.status, 400, url);
        }
        const form = new FormData();
        form.set('file', new File([png()], 'photo.png', { type: 'image/png' }));
        form.set('url', 'https://example.com/photo.png');
        const response = await route.onRequest(context('https://test/upload?uploadChannel=external', form));
        assert.equal(response.status, 200, await response.clone().text());
        await Promise.all(waits);
    });

    it('P1-30: SSRF guard rejects trailing-dot localhost and IPv6 loopback', () => {
        assert.equal(ssrfGuard.isSafeExternalUrl('http://localhost./x'), false);
        assert.equal(ssrfGuard.isSafeExternalUrl('http://[::1]/x'), false);
        assert.equal(ssrfGuard.isSafeExternalUrl('https://example.com/x.png'), true);
    });

    it('P0-8/P1-43: HF direct upload requires a valid sha256 and a getUploadUrl issuance', async () => {
        const getUrl = await loadFunction('functions/upload/huggingface/getUploadUrl.js', mocks);
        const bad = { fileSize: 24, fileName: 'photo.png', fileType: 'image/png', sha256: 'not-a-hash', fileSample: 'mock' };
        assert.equal((await getUrl.onRequestPost(context('https://test/upload/huggingface/getUploadUrl', JSON.stringify(bad)))).status, 400);
        const badSize = { ...bad, sha256: SHA256, fileSize: 0 };
        assert.equal((await getUrl.onRequestPost(context('https://test/upload/huggingface/getUploadUrl', JSON.stringify(badSize)))).status, 400);

        const body = { fileSize: 24, fileName: 'photo.png', fileType: 'image/png', sha256: SHA256, fileSample: 'mock' };
        const issued = await getUrl.onRequestPost(context('https://test/upload/huggingface/getUploadUrl', JSON.stringify(body)));
        assert.equal(issued.status, 200, await issued.clone().text());
        const { fullId, filePath } = await issued.json();

        const commit = await loadFunction('functions/upload/huggingface/commitUpload.js', { ...mocks, endUpload: async () => {} });
        // 没走 getUploadUrl 的 fullId 直接拒绝
        const forged = await commit.onRequestPost(context('https://test/upload/huggingface/commitUpload', JSON.stringify({ ...body, fullId: 'forged.png', filePath: 'x_forged.png' })));
        assert.equal(forged.status, 400);
        // filePath 与签发不一致拒绝
        const mismatched = await commit.onRequestPost(context('https://test/upload/huggingface/commitUpload', JSON.stringify({ ...body, fullId, filePath: 'other.png' })));
        assert.equal(mismatched.status, 400);
        // 正常提交成功
        const ok = await commit.onRequestPost(context('https://test/upload/huggingface/commitUpload', JSON.stringify({ ...body, fullId, filePath })));
        assert.equal(ok.status, 200, await ok.clone().text());
        // 同一个签发记录不能重放第二次
        const replay = await commit.onRequestPost(context('https://test/upload/huggingface/commitUpload', JSON.stringify({ ...body, fullId, filePath })));
        assert.equal(replay.status, 400);
        await Promise.all(waits);
    });

    it('P1-19/P2-62: random API skips expired files and falls back for manual orientation', async () => {
        const previousCaches = globalThis.caches;
        globalThis.caches = { default: { match: async () => null, put: async () => {} } };
        try {
            const route = await loadFunction('functions/random/index.js', {
                ...adaptive,
                fetchOthersConfig: async () => ({ randomImageAPI: { enabled: true, allowedDir: '' } }),
                readIndex: async () => ({ files: [
                    { id: 'old.png', metadata: { FileType: 'image/png', ExpiresAt: Date.now() - 1000 } },
                    { id: 'new.png', metadata: { FileType: 'image/png' } },
                ] }),
            });
            const response = await route.onRequest({ request: new Request('https://test/random?content=image'), env: {} });
            assert.deepEqual(await response.json(), { url: '/file/new.png' });

            // 手动指定方向、无宽高信息的图片：以前会被全部滤掉返回 {}，现在回落到不过滤的结果
            const noSize = await loadFunction('functions/random/index.js', {
                ...adaptive,
                fetchOthersConfig: async () => ({ randomImageAPI: { enabled: true, allowedDir: '' } }),
                readIndex: async () => ({ files: [
                    { id: 'plain.png', metadata: { FileType: 'image/png' } },
                ] }),
            });
            const manual = await noSize.onRequest({ request: new Request('https://test/random?content=image&orientation=landscape'), env: {} });
            assert.deepEqual(await manual.json(), { url: '/file/plain.png' });
        } finally {
            if (previousCaches === undefined) delete globalThis.caches;
            else globalThis.caches = previousCaches;
        }
    });

    it('P1-19: public list skips expired files', async () => {
        const previousCaches = globalThis.caches;
        globalThis.caches = { default: { match: async () => null, put: async () => {} } };
        try {
            const route = await loadFunction('functions/api/public/list.js', {
                fetchOthersConfig: async () => ({ publicBrowse: { enabled: true, allowedDir: '' } }),
                readIndex: async () => ({ success: true, files: [
                    { id: 'old.png', metadata: { FileType: 'image/png', TimeStamp: 1, FileSize: '1', ExpiresAt: Date.now() - 1000 } },
                    { id: 'new.png', metadata: { FileType: 'image/png', TimeStamp: 2, FileSize: '1' } },
                ], directories: [], totalCount: 2 }),
            });
            const response = await route.onRequest({ request: new Request('https://test/api/public/list'), env: {} });
            assert.equal(response.status, 200);
            const body = await response.json();
            assert.deepEqual(body.files.map(file => file.name), ['new.png']);
            assert.equal(body.totalCount, 1);
        } finally {
            if (previousCaches === undefined) delete globalThis.caches;
            else globalThis.caches = previousCaches;
        }
    });

    it('P2-51: whitelist mode blocks metadata-less historical files', async () => {
        const previousFetch = globalThis.fetch;
        globalThis.fetch = async () => new Response('placeholder', { headers: { 'Content-Type': 'image/png' } });
        try {
            const blocked = await fileTools.returnWithCheck(
                { url: new URL('https://test/file/x.png'), securityConfig: { access: { whiteListMode: true } }, fileAccess: {} },
                { metadata: null },
            );
            assert.equal(blocked.status, 403);
            const open = await fileTools.returnWithCheck(
                { url: new URL('https://test/file/x.png'), securityConfig: { access: { whiteListMode: false } }, fileAccess: {} },
                { metadata: null },
            );
            assert.equal(open.status, 200);
        } finally {
            globalThis.fetch = previousFetch;
        }
    });

    it('P2-52/P1-22: R2 out-of-range returns 416 and S3 errors map to 416', async () => {
        let r2Gets = 0;
        const route = await loadFunction('functions/file/[[path]].js', {
            ...mocks,
            ...fileExpiryHelpers,
            ...fileTools,
            ...imageTransform,
            fetchSecurityConfig: async () => ({ access: { whiteListMode: false } }),
            authenticate: async () => ({ authorized: false, authType: null }),
        });
        await db.put('r.png', '', { metadata: { Channel: 'CloudflareR2', FileType: 'image/png' } });
        const r2 = {
            async head() { return { size: 6 }; },
            async get(id, options) {
                r2Gets++;
                return {
                    body: new Response('source').body,
                    size: 6,
                    range: options?.range ? { offset: options.range.offset, length: options.range.length ?? 6 } : undefined,
                    writeHttpMetadata(headers) { headers.set('Content-Type', 'application/octet-stream'); },
                };
            },
        };
        const outOfRange = await route.onRequest({
            request: new Request('https://test/file/r.png', { headers: { Range: 'bytes=10-20' } }),
            url: new URL('https://test/file/r.png'),
            env: { img_r2: r2 },
            params: { path: 'r.png' },
            waitUntil(promise) { waits.push(promise); },
        });
        assert.equal(outOfRange.status, 416);
        assert.equal(r2Gets, 0);
        const inRange = await route.onRequest({
            request: new Request('https://test/file/r.png', { headers: { Range: 'bytes=0-1' } }),
            url: new URL('https://test/file/r.png'),
            env: { img_r2: r2 },
            params: { path: 'r.png' },
            waitUntil(promise) { waits.push(promise); },
        });
        assert.equal(inRange.status, 206);
        assert.equal(inRange.headers.get('Content-Range'), 'bytes 0-1/6');
    });

    it('P2-49: retryFailedChunks really caps concurrency at maxConcurrency', async () => {
        const { chunk, uploadId, ctx } = await initSession({ totalChunks: 6 });
        // 种子 multipart 记录，复用已有上传，不新建
        await db.put(`multipart_${uploadId}`, JSON.stringify({ uploadId: 'multipart', key: 'final.png' }), { expirationTtl: 3600 });
        const data = png();
        const failedChunks = [];
        for (let i = 0; i < 6; i++) {
            const key = `chunk_${uploadId}_${String(i).padStart(3, '0')}`;
            await db.put(key, data, {
                metadata: { originalFileName: 'photo.png', originalFileType: 'image/png', uploadId, totalChunks: 6, status: 'failed' },
                expirationTtl: 3600,
            });
            failedChunks.push({ key, index: i, hasData: true, status: 'failed' });
        }
        // 追踪 uploadPart 的真实并发数
        let inFlight = 0;
        let maxInFlight = 0;
        ctx.env.img_r2.resumeMultipartUpload = () => ({
            async uploadPart() {
                inFlight++;
                maxInFlight = Math.max(maxInFlight, inFlight);
                await new Promise((resolve) => setTimeout(resolve, 20));
                inFlight--;
                return { etag: 'etag' };
            },
            async complete() {},
        });
        const { success, results } = await chunk.retryFailedChunks(ctx, failedChunks, 'cfr2', {
            maxConcurrency: 3, batchSize: 6, maxRetries: 1, retryTimeout: 60000,
        });
        assert.equal(success, true);
        assert.equal(results.length, 6);
        assert.deepEqual(results.map((r) => r.success), [true, true, true, true, true, true]);
        // 结果顺序与传入顺序一致
        assert.deepEqual(results.map((r) => r.chunk.index), [0, 1, 2, 3, 4, 5]);
        // 旧实现会 6 路同时启动；worker 池一次最多 3 路
        assert.ok(maxInFlight <= 3, `max in-flight was ${maxInFlight}`);
        assert.ok(maxInFlight > 1, 'retries should still run concurrently');
    });
});
