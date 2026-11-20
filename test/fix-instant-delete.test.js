import assert from 'node:assert/strict';
import { loadFunction } from './helpers/loadFunction.js';
import { createContext } from './helpers/context.js';
import { managementFixture } from './helpers/management.js';
import { createDatabaseAdapter } from '../functions/utils/databaseAdapter.js';
import * as batchTools from '../functions/utils/deleteBatch.js';

// 即时删除/即时上图：点删除图片立即从列表消失（响应前索引已同步），
// 不必等远端存储删除完成；刷新后已删图片不再出现；批量删除整批只合
// 并一次索引；上传新图片后立即出现在图库。
describe('instant delete and instant upload', () => {
    let fixture, single, batch, index;

    beforeEach(async () => {
        fixture = await managementFixture();
        const db = createDatabaseAdapter({ img_url: fixture.db });
        fixture.mocks.getDatabase = () => db;
        const seed = fixture.seed;
        fixture.seed = async files => {
            await seed(files);
            for (const file of files) {
                await db.put(file.id, file.value ?? 'record-value', { metadata: file.metadata });
            }
        };
        single = await loadFunction('functions/api/manage/delete/[[path]].js', fixture.mocks);
        batch = await loadFunction('functions/api/manage/delete/batch.js', { ...fixture.mocks, ...batchTools, ...single });
        index = await loadFunction('functions/utils/indexManager.js', fixture.mocks);
    });

    function deleteContext(id, options = {}) {
        return createContext(`https://test/api/manage/delete/${id}`, {
            method: 'DELETE', env: fixture.env, params: { path: encodeURIComponent(id.replaceAll('/', ',')) }, ...options,
        });
    }

    function listContext() {
        return createContext('https://test/api/manage/list', { env: fixture.env });
    }

    async function readAll() {
        const result = await index.readIndex(listContext(), { count: -1, includeSubdirFiles: true });
        assert.equal(result.success, true, result.error);
        return result.files.map(file => file.id);
    }

    function pendingOpCount() {
        return [...fixture.db.records.keys()].filter(key => key.startsWith('manage@index@operation_')).length;
    }

    // 模拟 KV list 最终一致：刚写下的操作键暂时不在 list 结果里。
    function laggyList() {
        const originalList = fixture.db.list.bind(fixture.db);
        fixture.db.list = async options => {
            const result = await originalList(options);
            return { ...result, keys: result.keys.filter(key => !key.name.startsWith('manage@index@operation_')) };
        };
        return () => { fixture.db.list = originalList; };
    }

    it('single delete syncs the index before the response and defers the CDN purge', async () => {
        const id = 'album/photo.png';
        await fixture.seed([{ id, metadata: { Channel: 'CloudflareR2', FileType: 'image/png' } }]);
        const ctx = deleteContext(id);
        const response = await single.onRequest(ctx);
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), { success: true, fileId: id, existed: true });
        // 不排空后台任务：索引里已经没有这张图，刷新也不会重新出现
        assert.deepEqual(await readAll(), []);
        assert.equal(pendingOpCount(), 0);
        // R2 本地删除同步完成
        assert.equal(fixture.objects.has(id), false);
        await Promise.all(ctx.backgroundTasks);
        assert.equal(fixture.purges.filter(purge => purge[0] === 'file').length, 1);
    });

    it('deleted file does not reappear on refresh when KV list lags behind', async () => {
        const restore = laggyList();
        try {
            const id = 'album/photo.png';
            await fixture.seed([{ id, metadata: { Channel: 'CloudflareR2', FileType: 'image/png' } }]);
            const ctx = deleteContext(id);
            const response = await single.onRequest(ctx);
            assert.equal(response.status, 200);
            // list 暂时看不到刚记的操作，但直接合并已让它生效，刷新也看不到
            assert.deepEqual(await readAll(), []);
            // 操作记录留作保险：下次 list 看到它时幂等重放再清理
            assert.equal(pendingOpCount(), 1);
        } finally {
            restore();
        }
        assert.deepEqual(await readAll(), []);
        assert.equal(pendingOpCount(), 0);
    });

    it('batch delete merges the index once for the whole batch', async () => {
        const ids = ['a.png', 'b.png', 'c.png'];
        await fixture.seed(ids.map(id => ({ id, metadata: { Channel: 'CloudflareR2', FileType: 'image/png' } })));
        const ctx = createContext('https://test/api/manage/delete/batch', {
            method: 'POST', env: fixture.env,
            body: JSON.stringify({ fileIds: ids }),
            headers: { 'Content-Type': 'application/json' },
        });
        const response = await batch.onRequest(ctx);
        assert.equal(response.status, 200);
        const body = await response.json();
        assert.equal(body.success, true);
        assert.deepEqual(body.deleted, ids);
        // 不排空后台任务：三张图已全部从索引消失，且只记了一次批量操作
        assert.deepEqual(await readAll(), []);
        assert.equal(pendingOpCount(), 0);
        // 后台任务只有各文件的 CDN 清缓存，没有索引任务
        assert.equal(ctx.backgroundTasks.length, 3);
        await Promise.all(ctx.backgroundTasks);
        assert.equal(fixture.purges.filter(purge => purge[0] === 'file').length, 3);
        assert.deepEqual(await readAll(), []);
    });

    it('upload add appears in the gallery immediately even when KV list lags', async () => {
        await fixture.seed([]);
        const restore = laggyList();
        try {
            const ctx = listContext();
            const result = await index.addFileToIndex(ctx, 'new.png', { FileType: 'image/png', FileName: 'new.png' });
            assert.equal(result.success, true);
            // list 暂时看不到刚记的操作，但直接合并已让新图进图库
            assert.deepEqual(await readAll(), ['new.png']);
            assert.equal(pendingOpCount(), 1);
        } finally {
            restore();
        }
        assert.deepEqual(await readAll(), ['new.png']);
        assert.equal(pendingOpCount(), 0);
    });

    it('remove operations are not skipped by lastOperationId', async () => {
        // 操作 ID 是“毫秒时间戳_随机串”：同一毫秒内随机串更小的操作，
        // 字符串比较会排在 lastOperationId 之前，旧逻辑会永久跳过它。
        await fixture.db.put('manage@index@meta', JSON.stringify({
            chunkCount: 1, totalCount: 1, lastUpdated: Date.now(), lastOperationId: '1700000000000_zzzzzzz',
        }));
        await fixture.db.put('manage@index_0', JSON.stringify([{ id: 'a.png', metadata: { FileType: 'image/png' } }]));
        await fixture.db.put(
            'manage@index@operation_1700000000000_aaaaaaa',
            JSON.stringify({ type: 'remove', timestamp: 1700000000000, data: { fileId: 'a.png' } }),
        );
        assert.deepEqual(await readAll(), []);
        assert.equal(pendingOpCount(), 0);
    });
});
