import assert from 'node:assert/strict';
import { loadFunction, memoryDatabase } from './helpers/loadFunction.js';
import { createContext } from './helpers/context.js';
import { managementFixture } from './helpers/management.js';
import * as metadataSecurity from '../functions/utils/metadata/metadataSecurity.js';
import * as tagHelpers from '../functions/utils/tagHelpers.js';
import * as apiResponse from '../functions/utils/apiResponse.js';
import * as batchTools from '../functions/utils/deleteBatch.js';

// B 组回归测试：后台管理 API 与索引修复（P0-1/2/3/7、P1-13/14/15/17/18/20/24、P2-54/57/60/61/71、P1-46）。
describe('fix group B: manage API and index', () => {
    let fixture;

    beforeEach(async () => {
        fixture = await managementFixture();
    });

    async function loadTagService() {
        return loadFunction('functions/utils/tagService.js', {
            getDatabase: () => fixture.db,
            batchAddFilesToIndex: fixture.mocks.batchAddFilesToIndex,
            cleanPersistedMetadata: metadataSecurity.cleanPersistedMetadata,
            mergeTags: tagHelpers.mergeTags,
            validateTag: tagHelpers.validateTag,
            purgePublicFileListCache: fixture.mocks.purgePublicFileListCache,
            purgeRandomFileListCache: fixture.mocks.purgeRandomFileListCache,
            APIError: apiResponse.APIError,
            errorResult: apiResponse.errorResult,
        });
    }

    describe('P0-1 delete rejects system keys', () => {
        it('rejects manage@ keys on single delete and leaves the record intact', async () => {
            const tagService = await loadTagService();
            const single = await loadFunction('functions/api/manage/delete/[[path]].js', {
                ...fixture.mocks, validateFileId: tagService.validateFileId,
            });
            await fixture.db.put('manage@sysConfig@security', 'secret-value', { metadata: {} });
            const ctx = createContext('https://test/api/manage/delete/manage@sysConfig@security', {
                method: 'DELETE', env: fixture.env, params: { path: 'manage@sysConfig@security' },
            });
            const response = await single.onRequest(ctx);
            assert.equal(response.status, 400);
            assert.equal((await fixture.db.get('manage@sysConfig@security')), 'secret-value');
        });

        it('rejects manage@ keys in batch delete without deleting anything', async () => {
            const tagService = await loadTagService();
            const single = await loadFunction('functions/api/manage/delete/[[path]].js', {
                ...fixture.mocks, validateFileId: tagService.validateFileId,
            });
            const batch = await loadFunction('functions/api/manage/delete/batch.js', {
                ...fixture.mocks, ...batchTools, ...single, validateFileId: tagService.validateFileId,
            });
            await fixture.seed([{ id: 'photo.png', metadata: { Channel: 'CloudflareR2' } }]);
            await fixture.db.put('manage@index@meta', 'meta-value', { metadata: {} });
            const ctx = createContext('https://test/api/manage/delete/batch', {
                method: 'POST', env: fixture.env,
                body: JSON.stringify({ fileIds: ['photo.png', 'manage@index@meta'] }),
                headers: { 'Content-Type': 'application/json' },
            });
            const response = await batch.onRequest(ctx);
            assert.equal(response.status, 400);
            assert.equal((await fixture.db.get('manage@index@meta')), 'meta-value');
            assert.notEqual(await fixture.db.getWithMetadata('photo.png'), null);
        });

        it('still deletes normal file IDs', async () => {
            const tagService = await loadTagService();
            const single = await loadFunction('functions/api/manage/delete/[[path]].js', {
                ...fixture.mocks, validateFileId: tagService.validateFileId,
            });
            await fixture.seed([{ id: 'album/photo.png', metadata: { Channel: 'CloudflareR2' } }]);
            const ctx = createContext('https://test/api/manage/delete/album,photo.png', {
                method: 'DELETE', env: fixture.env, params: { path: 'album,photo.png' },
            });
            const response = await single.onRequest(ctx);
            assert.equal(response.status, 200);
            assert.equal(await fixture.db.getWithMetadata('album/photo.png'), null);
        });
    });

    describe('P0-2 same-site check for state-changing GETs', () => {
        it('rejects cross-site delete/move/block/white requests with 403', async () => {
            const single = await loadFunction('functions/api/manage/delete/[[path]].js', fixture.mocks);
            const move = await loadFunction('functions/api/manage/move/[[path]].js', fixture.mocks);
            const block = await loadFunction('functions/api/manage/block/[[path]].js', fixture.mocks);
            const white = await loadFunction('functions/api/manage/white/[[path]].js', fixture.mocks);
            await fixture.seed([{ id: 'photo.png', metadata: { Channel: 'CloudflareR2' } }]);
            const crossSite = { 'Sec-Fetch-Site': 'cross-site' };
            const cases = [
                [single, 'https://test/api/manage/delete/photo.png', { path: 'photo.png' }],
                [move, 'https://test/api/manage/move/photo.png?dist=new', { path: 'photo.png' }],
                [block, 'https://test/api/manage/block/photo.png', { path: 'photo.png' }],
                [white, 'https://test/api/manage/white/photo.png', { path: 'photo.png' }],
            ];
            for (const [route, url, params] of cases) {
                const ctx = createContext(url, { method: 'GET', env: fixture.env, params, headers: crossSite });
                assert.equal((await route.onRequest(ctx)).status, 403, url);
            }
            assert.notEqual(await fixture.db.getWithMetadata('photo.png'), null);
        });

        it('allows same-origin delete requests', async () => {
            const single = await loadFunction('functions/api/manage/delete/[[path]].js', fixture.mocks);
            await fixture.seed([{ id: 'photo.png', metadata: { Channel: 'CloudflareR2' } }]);
            const ctx = createContext('https://test/api/manage/delete/photo.png', {
                method: 'GET', env: fixture.env, params: { path: 'photo.png' },
                headers: { 'Sec-Fetch-Site': 'same-origin' },
            });
            assert.equal((await single.onRequest(ctx)).status, 200);
            assert.equal(await fixture.db.getWithMetadata('photo.png'), null);
        });
    });

    describe('P0-3 move target checks', () => {
        it('treats moving a file onto itself as an idempotent success without touching storage', async () => {
            const move = await loadFunction('functions/api/manage/move/[[path]].js', fixture.mocks);
            await fixture.seed([{ id: 'album/photo.png', metadata: { Channel: 'CloudflareR2', FileName: 'photo.png' } }]);
            const ctx = createContext('https://test/api/manage/move/album,photo.png?dist=album', {
                method: 'GET', env: fixture.env, params: { path: 'album,photo.png' },
            });
            const response = await move.onRequest(ctx);
            assert.equal(response.status, 200);
            assert.equal((await response.json()).newFileId, 'album/photo.png');
            assert.equal(fixture.objects.get('album/photo.png'), 'file-content');
            assert.deepEqual(ctx.backgroundTasks, []);
        });

        it('returns 409 when the move target already exists and keeps both records', async () => {
            const move = await loadFunction('functions/api/manage/move/[[path]].js', fixture.mocks);
            await fixture.seed([
                { id: 'album/photo.png', metadata: { Channel: 'CloudflareR2', FileName: 'photo.png' } },
                { id: 'new/photo.png', value: 'target-value', metadata: { Channel: 'CloudflareR2', FileName: 'photo.png' } },
            ]);
            const ctx = createContext('https://test/api/manage/move/album,photo.png?dist=new', {
                method: 'GET', env: fixture.env, params: { path: 'album,photo.png' },
            });
            const response = await move.onRequest(ctx);
            assert.equal(response.status, 409);
            assert.equal((await fixture.db.getWithMetadata('album/photo.png')).value, 'record-value');
            assert.equal((await fixture.db.getWithMetadata('new/photo.png')).value, 'target-value');
            assert.equal(fixture.objects.get('album/photo.png'), 'file-content');
            assert.deepEqual(ctx.backgroundTasks, []);
        });
    });

    describe('P0-7 list mutating actions require manage permission', () => {
        async function loadList(authenticate) {
            return loadFunction('functions/api/manage/list.js', {
                ...fixture.mocks, authenticate, AUTH_SCOPE: { ADMIN: 'admin' },
            });
        }

        it('rejects rebuild/merge-operations/delete-operations for list-only tokens', async () => {
            const route = await loadList(async ({ requiredPermission }) => ({
                authorized: requiredPermission !== 'manage', authType: 'admin',
            }));
            for (const action of ['rebuild', 'merge-operations', 'delete-operations']) {
                const ctx = createContext(`https://test/api/manage/list?action=${action}`, { env: fixture.env });
                assert.equal((await route.onRequest(ctx)).status, 401, action);
            }
        });

        it('allows the same actions with manage permission', async () => {
            const route = await loadList(async () => ({ authorized: true, authType: 'admin' }));
            const ctx = createContext('https://test/api/manage/list?action=delete-operations', { env: fixture.env });
            const response = await route.onRequest(ctx);
            assert.equal(response.status, 200);
            await Promise.all(ctx.backgroundTasks);
        });

        it('still serves plain list queries without re-checking manage permission', async () => {
            let manageChecks = 0;
            const route = await loadList(async ({ requiredPermission }) => {
                if (requiredPermission === 'manage') manageChecks++;
                return { authorized: true, authType: 'admin' };
            });
            await fixture.seed([{ id: 'a.png', metadata: { Channel: 'CloudflareR2', FileName: 'a.png' } }]);
            const ctx = createContext('https://test/api/manage/list?count=-1', { env: fixture.env });
            const response = await route.onRequest(ctx);
            assert.equal(response.status, 200);
            assert.equal(manageChecks, 0);
        });
    });

    describe('P1-24 rename rejects names that sanitize to empty', () => {
        it('returns 400 for /// and keeps the source record', async () => {
            const rename = await loadFunction('functions/api/manage/rename/[[path]].js', fixture.mocks);
            await fixture.seed([{ id: 'album/photo.png', metadata: { Channel: 'CloudflareR2', FileName: 'photo.png' } }]);
            const ctx = createContext('https://test/api/manage/rename/album,photo.png', {
                method: 'POST', env: fixture.env, params: { path: 'album,photo.png' },
                body: JSON.stringify({ newFileId: '///' }),
                headers: { 'Content-Type': 'application/json' },
            });
            assert.equal((await rename.onRequest(ctx)).status, 400);
            assert.notEqual(await fixture.db.getWithMetadata('album/photo.png'), null);
            assert.equal(await fixture.db.getWithMetadata(''), null);
        });
    });

    describe('P1-46 block/white return 404 for missing files', () => {
        it('returns 404 instead of crashing on a missing record', async () => {
            const block = await loadFunction('functions/api/manage/block/[[path]].js', fixture.mocks);
            const white = await loadFunction('functions/api/manage/white/[[path]].js', fixture.mocks);
            for (const route of [block, white]) {
                const ctx = createContext('https://test/api/manage/block/missing.png', {
                    env: fixture.env, params: { path: 'missing.png' },
                });
                assert.equal((await route.onRequest(ctx)).status, 404);
            }
        });
    });

    describe('P1-17 finalize rejects contradictory empty-index input', () => {
        async function loadFinalize(db) {
            return loadFunction('functions/api/manage/batch/index/finalize.js', {
                getDatabase: () => db, checkDatabaseConfig: () => ({ usingD1: false }),
            });
        }

        it('returns 400 for totalChunks=0 with totalFiles>0 and keeps the old index', async () => {
            const db = memoryDatabase();
            await db.put('manage@index@meta', JSON.stringify({ chunkCount: 1, totalCount: 1 }));
            await db.put('manage@index_0', JSON.stringify([{ id: 'a.png', metadata: {} }]));
            const finalize = await loadFinalize(db);
            const ctx = createContext('https://test/api/manage/batch/index/finalize', {
                method: 'POST', body: JSON.stringify({ sessionId: 'rebuild_1', totalChunks: 0, totalFiles: 500 }),
                headers: { 'Content-Type': 'application/json' },
            });
            assert.equal((await finalize.onRequest(ctx)).status, 400);
            assert.equal(JSON.parse(await db.get('manage@index@meta')).totalCount, 1);
            assert.deepEqual(JSON.parse(await db.get('manage@index_0')), [{ id: 'a.png', metadata: {} }]);
        });

        it('accepts totalChunks=0 with totalFiles=0 as an empty index', async () => {
            const db = memoryDatabase();
            const finalize = await loadFinalize(db);
            const ctx = createContext('https://test/api/manage/batch/index/finalize', {
                method: 'POST', body: JSON.stringify({ sessionId: 'rebuild_1', totalChunks: 0, totalFiles: 0 }),
                headers: { 'Content-Type': 'application/json' },
            });
            const response = await finalize.onRequest(ctx);
            assert.equal(response.status, 200);
            assert.equal((await response.json()).indexedCount, 0);
            assert.equal(JSON.parse(await db.get('manage@index@meta')).chunkCount, 0);
        });

        it('assembles chunks, writes metadata last and cleans excess old chunks', async () => {
            const db = memoryDatabase();
            await db.put('manage@index@meta', JSON.stringify({ chunkCount: 3, totalCount: 3 }));
            await db.put('manage@index_0', JSON.stringify([{ id: 'old0.png', metadata: {} }]));
            await db.put('manage@index_1', JSON.stringify([{ id: 'old1.png', metadata: {} }]));
            await db.put('manage@index_2', JSON.stringify([{ id: 'old2.png', metadata: {} }]));
            await db.put('chunk_rebuild_1_0', JSON.stringify({
                chunkId: 0, data: [{ id: 'new.png', metadata: { FileName: 'new.png' } }], recordCount: 1,
            }));
            const finalize = await loadFinalize(db);
            const ctx = createContext('https://test/api/manage/batch/index/finalize', {
                method: 'POST', body: JSON.stringify({ sessionId: 'rebuild_1', totalChunks: 1, totalFiles: 1 }),
                headers: { 'Content-Type': 'application/json' },
            });
            const response = await finalize.onRequest(ctx);
            assert.equal(response.status, 200);
            assert.equal((await response.json()).indexedCount, 1);
            assert.equal(JSON.parse(await db.get('manage@index@meta')).chunkCount, 1);
            assert.deepEqual(JSON.parse(await db.get('manage@index_0')), [{ id: 'new.png', metadata: { FileName: 'new.png' } }]);
            assert.equal(await db.get('manage@index_1'), null);
            assert.equal(await db.get('manage@index_2'), null);
        });
    });

    describe('P1-13 missing index chunk fails instead of silently dropping files', () => {
        it('readIndex reports failure when a chunk is missing', async () => {
            const db = memoryDatabase();
            const index = await loadFunction('functions/utils/indexManager.js', {
                getDatabase: () => db, checkDatabaseConfig: () => ({ usingD1: false }),
            });
            await db.put('manage@index@meta', JSON.stringify({ chunkCount: 2, totalCount: 2, lastUpdated: Date.now() }));
            await db.put('manage@index_0', JSON.stringify([{ id: 'a.png', metadata: { TimeStamp: 1 } }]));
            const ctx = createContext('https://test/api/manage/list', { env: {} });
            const result = await index.readIndex(ctx, { count: -1 });
            assert.equal(result.success, false);
            await Promise.all(ctx.backgroundTasks);
        });
    });

    describe('P1-15 rebuild keeps operations recorded during the rebuild', () => {
        it('replays an add operation after rebuild instead of dropping it', async () => {
            const ctx = createContext('https://test/api/manage/list', { env: fixture.env });
            await fixture.db.put('kept.png', 'record-value', { metadata: { Channel: 'CloudflareR2', FileName: 'kept.png', TimeStamp: 1 } });
            await fixture.mocks.addFileToIndex(ctx, 'late.png', { Channel: 'CloudflareR2', FileName: 'late.png', TimeStamp: 2 });
            const operationKeys = [...fixture.db.records.keys()].filter(key => key.startsWith('manage@index@operation_'));
            assert.equal(operationKeys.length, 1);
            const rebuilt = await fixture.mocks.rebuildIndex(ctx);
            assert.equal(rebuilt.success, true);
            await Promise.all(ctx.backgroundTasks);
            assert.deepEqual(
                [...fixture.db.records.keys()].filter(key => key.startsWith('manage@index@operation_')),
                operationKeys, 'operations must survive the rebuild',
            );
            const index = await fixture.readFiles(ctx);
            assert.deepEqual(index.files.map(file => file.id).sort(), ['kept.png', 'late.png']);
        });
    });

    describe('P1-20 KV fallback applies the same filters and pagination', () => {
        it('filters by search and file type and paginates when the index is unavailable', async () => {
            const route = await loadFunction('functions/api/manage/list.js', fixture.mocks);
            await fixture.db.put('album/a.png', 'v', { metadata: { Channel: 'CloudflareR2', FileName: 'a.png', FileType: 'image/png', Directory: 'album/', TimeStamp: 1 } });
            await fixture.db.put('album/b.mp4', 'v', { metadata: { Channel: 'CloudflareR2', FileName: 'b.mp4', FileType: 'video/mp4', Directory: 'album/', TimeStamp: 2 } });
            await fixture.db.put('album/sub/c.png', 'v', { metadata: { Channel: 'CloudflareR2', FileName: 'c.png', FileType: 'image/png', Directory: 'album/sub/', TimeStamp: 3 } });
            // 不写索引元数据：readIndex 失败，走 KV 兜底分支。
            // 后台重建会把索引写回来、让后续调用不再走兜底，因此挡住索引元数据的写入，
            // 让本测试的每次调用都稳定走兜底分支。
            const realPut = fixture.db.put.bind(fixture.db);
            fixture.db.put = async (key, value, options) => {
                if (key === 'manage@index@meta') throw new Error('index unavailable');
                return realPut(key, value, options);
            };
            const list = async query => {
                const ctx = createContext(`https://test/api/manage/list?${query}`, { env: fixture.env });
                const response = await route.onRequest(ctx);
                assert.equal(response.status, 200);
                await Promise.all(ctx.backgroundTasks);
                return response.json();
            };
            const images = await list('dir=album&count=-1&fileType=image');
            assert.equal(images.isIndexedResponse, false);
            assert.deepEqual(images.files.map(file => file.name), ['album/a.png']);
            assert.equal(images.totalCount, 1);
            const searched = await list('dir=album&count=-1&search=B.MP4');
            assert.deepEqual(searched.files.map(file => file.name), ['album/b.mp4']);
            const page = await list('dir=album&start=1&count=1');
            assert.equal(page.totalCount, 2);
            assert.equal(page.returnedCount, 1);
            assert.deepEqual(page.files.map(file => file.name), ['album/b.mp4']);
            const recursive = await list('dir=album&count=-1&recursive=true');
            assert.equal(recursive.totalCount, 3);
        });
    });

    describe('P1-18 restore writes restored files to the index', () => {
        it('makes restored files visible in the list and clears list caches', async () => {
            await fixture.seed([]); // 先建一个空索引，否则第一次读索引会失败并触发后台重建。
            const restore = await loadFunction('functions/api/manage/batch/restore/chunk.js', {
                getDatabase: () => fixture.db,
                cleanPersistedMetadata: metadataSecurity.cleanPersistedMetadata,
                batchAddFilesToIndex: fixture.mocks.batchAddFilesToIndex,
                purgePublicFileListCache: fixture.mocks.purgePublicFileListCache,
                purgeRandomFileListCache: fixture.mocks.purgeRandomFileListCache,
            });
            const ctx = createContext('https://test/api/manage/batch/restore/chunk', {
                method: 'POST', env: fixture.env,
                body: JSON.stringify({ type: 'files', data: {
                    'album/x.png': { value: 'v', metadata: { Channel: 'CloudflareR2', FileName: 'x.png', FileType: 'image/png', TimeStamp: 1 } },
                } }),
                headers: { 'Content-Type': 'application/json' },
            });
            const response = await restore.onRequest(ctx);
            assert.equal(response.status, 200);
            assert.equal((await response.json()).restoredCount, 1);
            await Promise.all(ctx.backgroundTasks);
            const index = await fixture.readFiles(ctx);
            assert.deepEqual(index.files.map(file => file.id), ['album/x.png']);
            assert.ok(fixture.purges.some(([kind]) => kind === 'random'));
            assert.ok(fixture.purges.some(([kind]) => kind === 'public'));
        });
    });

    describe('P2-54 metadata edits clear random/public list caches', () => {
        it('purges ancestor directories after a metadata change', async () => {
            const metadata = await loadFunction('functions/api/manage/metadata/[[path]].js', fixture.mocks);
            await fixture.seed([{ id: 'album/photo.png', metadata: { Channel: 'CloudflareR2', FileName: 'photo.png', TimeStamp: 1 } }]);
            const ctx = createContext('https://test/api/manage/metadata/album,photo.png', {
                method: 'PATCH', env: fixture.env, params: { path: 'album,photo.png' },
                body: JSON.stringify({ FileName: 'renamed.png' }),
                headers: { 'Content-Type': 'application/json' },
            });
            assert.equal((await metadata.onRequest(ctx)).status, 200);
            await Promise.all(ctx.backgroundTasks);
            assert.deepEqual(fixture.purges, [
                ['public', 'https://test', '', 'album'],
                ['random', 'https://test', '', 'album'],
            ]);
        });
    });

    describe('P2-57 autocomplete scans beyond the first 1000 files', () => {
        it('finds a tag that only exists on file 1002', async () => {
            const files = [];
            for (let i = 0; i < 1001; i++) {
                files.push({ id: `f${i}.png`, metadata: { FileName: `f${i}.png`, Tags: ['common'], TimeStamp: i } });
            }
            files.push({ id: 'z/last.png', metadata: { FileName: 'last.png', Tags: ['raretarget'], TimeStamp: 1001 } });
            await fixture.seed(files);
            const route = await loadFunction('functions/api/manage/tags/autocomplete.js', {
                ...fixture.mocks, filterTagsByPrefix: tagHelpers.filterTagsByPrefix,
            });
            const ctx = createContext('https://test/api/manage/tags/autocomplete?prefix=rare', { env: fixture.env });
            const response = await route.onRequest(ctx);
            assert.equal(response.status, 200);
            const body = await response.json();
            assert.deepEqual(body.tags, ['raretarget']);
            assert.equal(body.scannedFiles, 1002);
            assert.equal(body.truncated, false);
        });
    });

    describe('P2-60 merge save cleans excess old chunks', () => {
        it('deletes stale index chunks after files are removed', async () => {
            const db = memoryDatabase();
            const index = await loadFunction('functions/utils/indexManager.js', {
                getDatabase: () => db, checkDatabaseConfig: () => ({ usingD1: false }),
            });
            await db.put('manage@index@meta', JSON.stringify({ chunkCount: 3, totalCount: 3, lastUpdated: Date.now() }));
            await db.put('manage@index_0', JSON.stringify([{ id: 'a.png', metadata: { TimeStamp: 1 } }]));
            await db.put('manage@index_1', JSON.stringify([{ id: 'b.png', metadata: { TimeStamp: 2 } }]));
            await db.put('manage@index_2', JSON.stringify([{ id: 'c.png', metadata: { TimeStamp: 3 } }]));
            const ctx = createContext('https://test/api/manage/list', { env: {} });
            await index.removeFileFromIndex(ctx, 'b.png');
            await index.removeFileFromIndex(ctx, 'c.png');
            const result = await index.readIndex(ctx, { count: -1 });
            assert.equal(result.success, true);
            assert.deepEqual(result.files.map(file => file.id), ['a.png']);
            assert.equal(await db.get('manage@index_1'), null);
            assert.equal(await db.get('manage@index_2'), null);
            await Promise.all(ctx.backgroundTasks);
        });
    });

    describe('P2-61 quota stats bucket files without ChannelName', () => {
        it('falls back to Channel, then to unknown', async () => {
            await fixture.seed([]); // 先建一个空索引，否则第一次读索引会失败并触发后台重建。
            const ctx = createContext('https://test/api/manage/list', { env: fixture.env });
            await fixture.mocks.addFileToIndex(ctx, 'legacy.png', { Channel: 'Telegram', FileName: 'legacy.png', FileSize: 2, TimeStamp: 1 });
            await fixture.mocks.addFileToIndex(ctx, 'noname.png', { FileName: 'noname.png', FileSize: 3, TimeStamp: 2 });
            await fixture.readFiles(ctx);
            const meta = await fixture.mocks.getIndexMeta(ctx);
            assert.equal(meta.channelStats.Telegram.usedMB, 2);
            assert.equal(meta.channelStats.Telegram.fileCount, 1);
            assert.equal(meta.channelStats.unknown.usedMB, 3);
            assert.equal(meta.channelStats.unknown.fileCount, 1);
            assert.equal(meta.totalSizeMB, 5);
        });
    });

    describe('P2-71 applyTagItems retries on a concurrent tag change', () => {
        it('merges against the fresh record instead of overwriting the concurrent edit', async () => {
            const tagService = await loadTagService();
            await fixture.db.put('photo.png', 'record-value', {
                metadata: { Channel: 'CloudflareR2', FileName: 'photo.png', Tags: ['a'], TimeStamp: 1 },
            });
            // 模拟另一个写者在我们读-改-写之间提交了 Tags ['a', 'concurrent']。
            const realGet = fixture.db.getWithMetadata.bind(fixture.db);
            let getCalls = 0;
            fixture.db.getWithMetadata = async key => {
                const record = await realGet(key);
                getCalls++;
                if (getCalls === 2 && record) {
                    const concurrent = { ...record, metadata: { ...record.metadata, Tags: ['a', 'concurrent'] } };
                    await fixture.db.put(key, record.value, { metadata: concurrent.metadata });
                    return concurrent;
                }
                return record;
            };
            const ctx = createContext('https://test/api/manage/tags/apply', { env: fixture.env });
            const result = await tagService.applyTagItems(ctx, [{ fileId: 'photo.png', tags: ['mine'] }], 'add');
            await Promise.all(ctx.backgroundTasks);
            assert.equal(result.success, true);
            assert.deepEqual((await fixture.db.getWithMetadata('photo.png')).metadata.Tags, ['a', 'concurrent', 'mine']);
        });
    });
});
