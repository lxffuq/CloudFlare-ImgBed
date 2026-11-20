import assert from 'node:assert/strict';
import { loadFunction, memoryDatabase } from './helpers/loadFunction.js';
import * as expiration from '../functions/utils/auth/tokenExpiration.js';
import * as passwords from '../functions/utils/auth/passwordHash.js';
import { getBackendType, checkDatabaseConfig, createDatabaseAdapter } from '../functions/utils/databaseAdapter.js';
import { D1Database } from '../functions/utils/d1Database.js';

function request(path, { headers = {}, method = 'GET', body } = {}) {
    const init = { headers, method };
    if (body !== undefined) init.body = body;
    return new Request(`https://test${path}`, init);
}

function basicAuth(user, pass) {
    return `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}`;
}

describe('fix group A: P0-4 WebDAV empty credentials are rejected', () => {
    let dav;
    let othersConfig;
    let db;
    let originalFetch;

    beforeEach(async () => {
        db = memoryDatabase();
        othersConfig = { webDAV: { enabled: true, username: '', password: '', internalToken: 'internal-tok' } };
        dav = await loadFunction('functions/dav/[[path]].js', {
            fetchOthersConfig: async () => othersConfig,
            getDatabase: () => db,
            createApiToken: async () => ({ token: 'new-tok', id: 'new-id' }),
        });
        originalFetch = globalThis.fetch;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    it('rejects every DAV request when the username or password is empty', async () => {
        for (const creds of [{ username: '', password: '' }, { username: 'admin', password: '' }, { username: '', password: 'secret' }]) {
            othersConfig.webDAV.username = creds.username;
            othersConfig.webDAV.password = creds.password;
            for (const method of ['OPTIONS', 'PUT']) {
                const response = await dav.onRequest({ request: request('/dav/file.txt', { method }), env: {} });
                assert.equal(response.status, 403, `${method} with ${JSON.stringify(creds)}`);
            }
        }
    });

    it('accepts a password containing colons (split on the first colon only)', async () => {
        othersConfig.webDAV.username = 'admin';
        othersConfig.webDAV.password = 'a:b:c';
        const response = await dav.onRequest({
            request: request('/dav/', { method: 'OPTIONS', headers: { Authorization: basicAuth('admin', 'a:b:c') } }),
            env: {},
        });
        assert.equal(response.status, 200);
    });

    it('rejects wrong credentials and returns 405 for MKCOL', async () => {
        othersConfig.webDAV.username = 'admin';
        othersConfig.webDAV.password = 'secret';
        const wrong = await dav.onRequest({
            request: request('/dav/', { method: 'OPTIONS', headers: { Authorization: basicAuth('admin', 'nope') } }),
            env: {},
        });
        assert.equal(wrong.status, 403);

        const mkcol = await dav.onRequest({
            request: request('/dav/newdir', { method: 'MKCOL', headers: { Authorization: basicAuth('admin', 'secret') } }),
            env: {},
        });
        assert.equal(mkcol.status, 405);
    });

    it('returns 500 (not 204) when a folder delete partially fails', async () => {
        othersConfig.webDAV.username = 'admin';
        othersConfig.webDAV.password = 'secret';
        const auth = { Authorization: basicAuth('admin', 'secret') };

        globalThis.fetch = async () => new Response(JSON.stringify({ success: true, failed: ['a/b.jpg'], deleted: [], missing: [] }), {
            headers: { 'Content-Type': 'application/json' },
        });
        const partial = await dav.onRequest({
            request: request('/dav/a/', { method: 'DELETE', headers: auth }),
            env: {},
        });
        assert.equal(partial.status, 500);

        globalThis.fetch = async () => new Response(JSON.stringify({ success: true, failed: [], deleted: ['a/b.jpg'], missing: [] }), {
            headers: { 'Content-Type': 'application/json' },
        });
        const full = await dav.onRequest({
            request: request('/dav/a/', { method: 'DELETE', headers: auth }),
            env: {},
        });
        assert.equal(full.status, 204);
    });
});

describe('fix group A: P0-5 security config read failure is fail-closed', () => {
    it('authenticate() returns configError instead of falling back to an empty config', async () => {
        const db = memoryDatabase();
        const core = await loadFunction('functions/utils/auth/authCore.js', {
            fetchSecurityConfig: async () => { throw new Error('KV down'); },
            getDatabase: () => db,
            validateApiToken: async () => ({ valid: false }),
            validateSession: async () => ({ valid: false }),
            verifyPassword: async () => false,
        });
        const result = await core.authenticate({ env: {}, request: request('/'), url: new URL('https://test/') });
        assert.deepEqual(result, { authorized: false, authType: null, configError: true });
    });

    it('manage middleware turns a config failure into 503, not 401', async () => {
        const middleware = await loadFunction('functions/api/manage/_middleware.js', {
            authenticate: async () => ({ authorized: false, authType: null, configError: true }),
            AUTH_SCOPE: { ADMIN: 'admin', USER: 'user', EITHER: 'either' },
        });
        const context = { env: {}, request: request('/api/manage/list'), next: async () => assert.fail('handler must not run') };
        const response = await middleware.onRequest[1](context);
        assert.equal(response.status, 503);
    });
});

describe('fix group A: P0-6 API tokens no longer escalate to admin', () => {
    let core;

    beforeEach(async () => {
        const db = memoryDatabase();
        const config = {
            auth: { admin: { adminUsername: 'admin', adminPassword: 'password' }, user: { authCode: 'user-code' } },
            access: { sessionSecure: false, adminSessionMaxAge: 14, userSessionMaxAge: 14 },
        };
        core = await loadFunction('functions/utils/auth/authCore.js', {
            fetchSecurityConfig: async () => config,
            getDatabase: () => db,
            validateApiToken: async (req, database, requiredPermission) => {
                const header = req.headers.get('Authorization');
                if (header !== 'Bearer good-token') return { valid: false };
                if (requiredPermission !== null && requiredPermission !== 'manage') return { valid: false, error: 'missing permission' };
                return { valid: true };
            },
            validateSession: async () => ({ valid: false }),
            verifyPassword: async () => false,
        });
    });

    it('returns authType token for a valid API token, never admin', async () => {
        const req = request('/', { headers: { Authorization: 'Bearer good-token' } });
        assert.deepEqual(
            await core.authenticate({ env: {}, request: req, url: new URL(req.url), requiredPermission: 'manage' }),
            { authorized: true, authType: 'token' },
        );
    });

    it('still grants admin authType to a real admin session', async () => {
        const coreWithSession = await loadFunction('functions/utils/auth/authCore.js', {
            fetchSecurityConfig: async () => ({
                auth: { admin: { adminUsername: 'admin', adminPassword: 'password' }, user: { authCode: 'user-code' } },
            }),
            getDatabase: () => memoryDatabase(),
            validateApiToken: async () => ({ valid: false }),
            validateSession: async (env, req, authType) => (authType === 'admin' ? { valid: true } : { valid: false }),
            verifyPassword: async () => false,
        });
        const req = request('/');
        assert.deepEqual(
            await coreWithSession.authenticate({ env: {}, request: req, url: new URL(req.url) }),
            { authorized: true, authType: 'admin' },
        );
    });

    it('dualAuthCheck forwards the per-endpoint required permission', async () => {
        let seen = null;
        const dualAuth = await loadFunction('functions/utils/auth/dualAuth.js', {
            authenticate: async (options) => { seen = options; return { authorized: true, authType: 'token' }; },
            AUTH_SCOPE: { ADMIN: 'admin', USER: 'user', EITHER: 'either' },
        });
        await dualAuth.dualAuthCheck({}, new URL('https://test/api/fetchRes'), request('/api/fetchRes'), { requiredPermission: 'manage' });
        assert.equal(seen.requiredPermission, 'manage');
        assert.equal(seen.authScope, 'either');
        await dualAuth.dualAuthCheck({}, new URL('https://test/api/channels'), request('/api/channels'));
        assert.equal(seen.requiredPermission, null);
    });
});

describe('fix group A: P2-25 settings export strips secrets', () => {
    it('exports token metadata without token values or password hashes', async () => {
        const db = memoryDatabase();
        await db.put('manage@sysConfig@security', JSON.stringify({
            auth: { admin: { adminUsername: 'admin', adminPassword: '$pbkdf2$salt$hash' }, user: { authCode: '$pbkdf2$salt$hash2' } },
            apiTokens: { tokens: { id1: { name: 't1', token: 'imgbed_secret-value', permissions: ['list'] } } },
        }));
        await db.put('manage@sysConfig@others', JSON.stringify({ telemetry: { enabled: false } }));
        await db.put('manage@index', JSON.stringify({ files: [] }));
        const settings = await loadFunction('functions/api/manage/batch/settings.js', {
            getDatabase: () => db,
        });
        const response = await settings.onRequestGet({ env: {} });
        assert.equal(response.status, 200);
        const body = await response.json();
        assert.equal(body.success, true);
        const security = body.settings['sysConfig@security'];
        assert.equal(security.apiTokens.tokens.id1.token, undefined);
        assert.equal(security.apiTokens.tokens.id1.name, 't1');
        assert.equal(security.auth.admin.adminPassword, undefined);
        assert.equal(security.auth.user.authCode, undefined);
        assert.equal(security.auth.admin.adminUsername, 'admin');
        assert.deepEqual(body.settings['sysConfig@others'], { telemetry: { enabled: false } });
        assert.equal(body.settings.index, undefined);
        assert.equal(JSON.stringify(body).includes('imgbed_secret-value'), false);
        assert.equal(JSON.stringify(body).includes('$pbkdf2$'), false);
    });
});

describe('fix group A: P2-27 resetAuth revokes API tokens', () => {
    it('deletes all apiTokens and notes that env credentials stay valid', async () => {
        const db = memoryDatabase();
        await db.put('manage@sysConfig@security', JSON.stringify({
            auth: { admin: { adminUsername: 'admin', adminPassword: 'x' } },
            apiTokens: { tokens: { a: { token: 't1' }, b: { token: 't2' } } },
            access: { whiteListMode: false },
        }));
        const resetAuth = await loadFunction('functions/api/auth/resetAuth.js', {
            getDatabase: () => db,
            destroySessionsByAuthType: async () => 1,
        });
        const response = await resetAuth.onRequestGet({
            request: request('/api/resetAuth?key=secret'),
            env: { RESET_KEY: 'secret' },
        });
        assert.equal(response.status, 200);
        const body = await response.json();
        assert.equal(body.tokensRevoked, 2);
        assert.match(body.note, /BASIC_USER/);
        const remaining = JSON.parse(await db.get('manage@sysConfig@security'));
        assert.equal(remaining.auth, undefined);
        assert.equal(remaining.apiTokens, undefined);
        assert.equal(remaining.access.whiteListMode, false);
    });
});

describe('fix group A: P2-28 username-only admin login is rejected', () => {
    async function loginWith(config) {
        const adminLogin = await loadFunction('functions/api/auth/adminLogin.js', {
            fetchSecurityConfig: async () => config,
            verifyPassword: async (input, stored) => input === 'correct' && stored === 'hashed',
            rehashIfNeeded: async () => {},
            createSession: async () => ({ token: 't', cookie: 'admin_session=t; Path=/; HttpOnly' }),
            getDatabase: () => memoryDatabase(),
        });
        return adminLogin.onRequestPost({
            request: request('/api/auth/adminLogin', {
                method: 'POST',
                body: JSON.stringify({ username: 'admin', password: 'correct' }),
                headers: { 'Content-Type': 'application/json' },
            }),
            env: {},
        });
    }

    it('refuses login when only the username is configured', async () => {
        const response = await loginWith({
            auth: { admin: { adminUsername: 'admin', adminPassword: '' }, user: { authCode: '' } },
        });
        assert.equal(response.status, 401);
        assert.match(await response.text(), /password/i);
    });

    it('still allows login when both username and password are configured', async () => {
        const response = await loginWith({
            auth: { admin: { adminUsername: 'admin', adminPassword: 'hashed' }, user: { authCode: '' } },
        });
        assert.equal(response.status, 200);
    });

    it('keeps the documented first-deploy open access when nothing is configured', async () => {
        const response = await loginWith({
            auth: { admin: { adminUsername: '', adminPassword: '' }, user: { authCode: '' } },
        });
        assert.equal(response.status, 200);
    });
});

describe('fix group A: P2-46/47 manage errors do not leak stacks', () => {
    it('returns a generic 500 without the error message or stack', async () => {
        const middleware = await loadFunction('functions/api/manage/_middleware.js', {
            authenticate: async () => ({ authorized: true, authType: 'admin' }),
            AUTH_SCOPE: { ADMIN: 'admin', USER: 'user', EITHER: 'either' },
        });
        const context = {
            env: {},
            request: request('/api/manage/list'),
            next: async () => { throw new Error('secret-stack-marker'); },
        };
        const response = await middleware.onRequest[0](context);
        assert.equal(response.status, 500);
        const text = await response.text();
        assert.equal(text.includes('secret-stack-marker'), false);
        assert.deepEqual(JSON.parse(text), { error: 'Internal Server Error' });
    });
});

describe('fix group A: P2-55/56/63/64 API token handling', () => {
    let tokens;
    let db;

    beforeEach(async () => {
        db = memoryDatabase();
        await db.put('manage@sysConfig@security', JSON.stringify({
            apiTokens: {
                tokens: {
                    good: { name: 'good', owner: 'me', permissions: ['list'], createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', token: 'imgbed_0123456789abcdef', expiresAt: null, autoDelete: false },
                    broken: { name: 'broken', owner: 'me', permissions: ['list'], createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', expiresAt: null, autoDelete: false },
                },
            },
        }));
        tokens = await loadFunction('functions/api/manage/apiTokens.js', {
            getDatabase: () => db,
            filterAutoDeleteTokens: expiration.filterAutoDeleteTokens,
        });
    });

    function context(req) {
        return { request: req, env: {} };
    }

    it('returns 404 when deleting or updating a missing token', async () => {
        const del = await tokens.onRequest(context(request('/api/manage/apiTokens?id=nope', { method: 'DELETE' })));
        assert.equal(del.status, 404);
        const put = await tokens.onRequest(context(request('/api/manage/apiTokens', {
            method: 'PUT',
            body: JSON.stringify({ tokenId: 'nope', permissions: ['list'] }),
            headers: { 'Content-Type': 'application/json' },
        })));
        assert.equal(put.status, 404);
    });

    it('lists a token record without a token field as an empty string instead of 500', async () => {
        const response = await tokens.onRequest(context(request('/api/manage/apiTokens')));
        assert.equal(response.status, 200);
        const body = await response.json();
        assert.equal(body.tokens.find(t => t.id === 'broken').token, '');
        assert.equal(body.tokens.find(t => t.id === 'good').token, 'imgbed_01234567...');
    });

    it('rejects non-whitelist permissions and illegal expiresAt on create', async () => {
        for (const body of [
            { name: 'x', permissions: ['bogus'], owner: 'me' },
            { name: 'x', permissions: 'list', owner: 'me' },
            { name: 'x', permissions: ['list'], owner: 'me', expiresAt: 'not-a-date' },
            { name: 'x', permissions: ['list'], owner: 'me', expiresAt: 12345 },
        ]) {
            const response = await tokens.onRequest(context(request('/api/manage/apiTokens', {
                method: 'POST',
                body: JSON.stringify(body),
                headers: { 'Content-Type': 'application/json' },
            })));
            assert.equal(response.status, 400, JSON.stringify(body));
        }
        const ok = await tokens.onRequest(context(request('/api/manage/apiTokens', {
            method: 'POST',
            body: JSON.stringify({ name: 'x', permissions: ['list'], owner: 'me', expiresAt: null }),
            headers: { 'Content-Type': 'application/json' },
        })));
        assert.equal(ok.status, 200);
    });

    it('validates token fields in createApiToken itself', async () => {
        assert.equal(tokens.validateTokenFields(['list', 'manage'], null), null);
        assert.equal(tokens.validateTokenFields([], '2030-01-01T00:00:00.000Z'), null);
        assert.match(tokens.validateTokenFields(['list', 'nope'], null), /permissions/);
        assert.match(tokens.validateTokenFields(['list'], 'yesterday-ish'), /expiresAt/);
        await assert.rejects(() => tokens.createApiToken(db, 'x', ['bogus'], 'me', null, false));
    });

    it('rejects tokens whose permissions are not an array (no substring match, no crash)', async () => {
        const validator = await loadFunction('functions/utils/auth/tokenValidator.js', {
            getTokenData: async () => ({ permissions: 'list', expiresAt: null }),
            isExpired: expiration.isExpired,
        });
        const req = request('/', { headers: { Authorization: 'Bearer t' } });
        assert.deepEqual(await validator.validateApiToken(req, db, 'list'), { valid: false, error: '缺少list权限' });
        assert.deepEqual(await validator.validateApiToken(req, db, 'ist'), { valid: false, error: '缺少ist权限' });
    });

    it('treats an illegal expiresAt as expired', () => {
        assert.equal(expiration.isExpired('not-a-date'), true);
        assert.equal(expiration.isExpired(null), false);
        assert.equal(expiration.isExpired('2000-01-01T00:00:00.000Z'), true);
        assert.equal(expiration.isExpired('2999-01-01T00:00:00.000Z'), false);
    });
});

describe('fix group A: P2-74 plaintext passwords use constant-time comparison', () => {
    it('still verifies plaintext passwords and rejects wrong ones', async () => {
        assert.equal(await passwords.verifyPassword('pw', 'pw'), true);
        assert.equal(await passwords.verifyPassword('wrong', 'pw'), false);
    });
});

describe('fix group A: P2-65/70 session expiry handling', () => {
    let sessions;
    let db;

    beforeEach(async () => {
        db = memoryDatabase();
        sessions = await loadFunction('functions/utils/auth/sessionManager.js', {
            ...passwords,
            getDatabase: () => db,
            fetchSecurityConfig: async () => ({ access: { sessionSecure: false, adminSessionMaxAge: 7, userSessionMaxAge: 2 } }),
            normalizeSessionMaxAgeDays: (v) => (typeof v === 'number' && v >= 1 && v <= 365 ? Math.floor(v) : 14),
            sessionMaxAgeDaysToTtl: (v) => (typeof v === 'number' && v >= 1 && v <= 365 ? Math.floor(v) : 14) * 86400,
        });
    });

    it('destroySessionsByAuthType skips unreadable records and only deletes confirmed-corrupt ones', async () => {
        await db.put('manage@session@good-admin', JSON.stringify({ authType: 'admin', expiresAt: Date.now() + 60000 }));
        await db.put('manage@session@user', JSON.stringify({ authType: 'user', expiresAt: Date.now() + 60000 }));
        await db.put('manage@session@corrupt', '{');
        const throwingDb = {
            ...db,
            async get(key) {
                if (key === 'manage@session@unreadable') throw new Error('D1 down');
                return db.get(key);
            },
        };
        await db.put('manage@session@unreadable', JSON.stringify({ authType: 'admin', expiresAt: Date.now() + 60000 }));
        const sessionsWithThrowingDb = await loadFunction('functions/utils/auth/sessionManager.js', {
            ...passwords,
            getDatabase: () => throwingDb,
            fetchSecurityConfig: async () => ({ access: {} }),
            normalizeSessionMaxAgeDays: (v) => 14,
            sessionMaxAgeDaysToTtl: (v) => 14 * 86400,
        });
        const destroyed = await sessionsWithThrowingDb.destroySessionsByAuthType({}, 'admin');
        assert.equal(destroyed, 2); // good-admin + corrupt; unreadable skipped, user kept
        assert.notEqual(await db.get('manage@session@unreadable'), null);
        assert.equal(await db.get('manage@session@user') === null, false);
        assert.equal(await db.get('manage@session@good-admin'), null);
        assert.equal(await db.get('manage@session@corrupt'), null);
    });

    it('creating a session sweeps already-expired sessions', async () => {
        await db.put('manage@session@expired', JSON.stringify({ authType: 'user', expiresAt: 0 }));
        await db.put('manage@session@alive', JSON.stringify({ authType: 'user', expiresAt: Date.now() + 60000 }));
        await sessions.createSession({}, 'admin');
        assert.equal(await db.get('manage@session@expired'), null);
        assert.notEqual(await db.get('manage@session@alive'), null);
    });
});

describe('fix group A: P2-66 one backend decision', () => {
    it('reports KV when both KV and D1 are bound, matching the adapter', () => {
        const env = { img_url: { get() {} }, img_d1: { prepare() {} } };
        assert.equal(getBackendType(env), 'kv');
        assert.deepEqual(checkDatabaseConfig(env), { hasD1: true, hasKV: true, usingD1: false, usingKV: true, configured: true });
        assert.equal(createDatabaseAdapter(env).kv, env.img_url);
    });

    it('reports D1 only when KV is absent', () => {
        const env = { img_d1: { prepare() {} } };
        assert.equal(getBackendType(env), 'd1');
        assert.deepEqual(checkDatabaseConfig(env), { hasD1: true, hasKV: false, usingD1: true, usingKV: false, configured: true });
    });
});

describe('fix group A: P2-67 D1 LIKE escaping and P2-65 session expiresAt', () => {
    function fakeD1(capture) {
        return {
            prepare(sql) {
                return {
                    bind(...params) {
                        capture.sql = sql;
                        capture.params = params;
                        return {
                            all: async () => ({ results: [] }),
                            first: async () => null,
                            run: async () => ({ meta: { changes: 1 } }),
                        };
                    },
                };
            },
        };
    }

    it('escapes _, % and \\ in list prefixes', async () => {
        const capture = {};
        const d1 = new D1Database(fakeD1(capture));
        await d1.listFiles({ prefix: 'a_b%c\\d', limit: 10 });
        assert.match(capture.sql, /ESCAPE/);
        assert.equal(capture.params[0], 'a\\_b\\%c\\\\d%');
    });

    it('stores expiresAt for session records when only expirationTtl is given', async () => {
        const capture = {};
        const d1 = new D1Database(fakeD1(capture));
        const before = Date.now();
        await d1.put('manage@session@tok', JSON.stringify({ authType: 'admin' }), { expirationTtl: 3600 });
        const stored = JSON.parse(capture.params[1]);
        assert.ok(stored.expiresAt >= before + 3600 * 1000);
        assert.ok(stored.expiresAt <= Date.now() + 3600 * 1000);
    });
});

describe('fix group A: P2-68 purgeCache returns failures to the caller', () => {
    let purge;
    let originalFetch;

    beforeEach(async () => {
        purge = await loadFunction('functions/utils/purgeCache.js', {
            fetchOthersConfig: async () => ({ cloudflareApiToken: { CF_ZONE_ID: 'zone', CF_EMAIL: 'a@b.c', CF_API_KEY: 'key' } }),
        });
        originalFetch = globalThis.fetch;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    it('returns true on success and false on API failure, with a JSON body', async () => {
        let sentBody = null;
        globalThis.fetch = async (url, options) => {
            sentBody = options.body;
            return { ok: true, status: 200 };
        };
        assert.equal(await purge.purgeCFCache({}, 'https://example.com/file/a"b.jpg'), true);
        assert.deepEqual(JSON.parse(sentBody), { files: ['https://example.com/file/a"b.jpg'] });

        globalThis.fetch = async () => ({ ok: false, status: 500 });
        assert.equal(await purge.purgeCFCache({}, 'https://example.com/file/x.jpg'), false);

        globalThis.fetch = async () => { throw new Error('network down'); };
        assert.equal(await purge.purgeCFCache({}, 'https://example.com/file/x.jpg'), false);
    });

    it('returns true when Cloudflare API is not configured', async () => {
        const unconfigured = await loadFunction('functions/utils/purgeCache.js', {
            fetchOthersConfig: async () => ({ cloudflareApiToken: {} }),
        });
        assert.equal(await unconfigured.purgeCFCache({}, 'https://example.com/file/x.jpg'), true);
    });
});

describe('fix group A: P2-69 directoryTree cacheTime validation', () => {
    async function treeResponse(cacheTime) {
        const directoryTree = await loadFunction('functions/api/directoryTree.js', {
            getDirectoryTree: async () => ({ name: 'root' }),
            dualAuthCheck: async () => ({ authorized: true, authType: 'admin' }),
            fetchPageConfig: async () => ({ config: [] }),
        });
        const query = cacheTime === undefined ? '' : `?cacheTime=${encodeURIComponent(cacheTime)}`;
        return directoryTree.onRequestGet({ env: {}, request: request(`/api/directoryTree${query}`) });
    }

    it('clamps cacheTime to 0-3600 and defaults illegal values to 60', async () => {
        assert.equal((await treeResponse('abc')).headers.get('Cache-Control'), 'private, max-age=60');
        assert.equal((await treeResponse('99999')).headers.get('Cache-Control'), 'private, max-age=3600');
        assert.equal((await treeResponse('-5')).headers.get('Cache-Control'), 'private, max-age=0');
        assert.equal((await treeResponse('30')).headers.get('Cache-Control'), 'private, max-age=30');
        assert.equal((await treeResponse()).headers.get('Cache-Control'), 'private, max-age=60');
    });
});

describe('fix group A: P2-72/73 fetchRes limits and SSRF bypass', () => {
    let fetchRes;
    let originalFetch;
    let seenAuthOptions;

    beforeEach(async () => {
        seenAuthOptions = null;
        fetchRes = await loadFunction('functions/api/fetchRes.js', {
            dualAuthCheck: async (env, url, req, options) => {
                seenAuthOptions = options;
                return { authorized: true, authType: 'admin' };
            },
        });
        originalFetch = globalThis.fetch;
    });

    afterEach(() => {
        globalThis.fetch = originalFetch;
    });

    function postFetchRes(url, fetchStub) {
        globalThis.fetch = fetchStub;
        return fetchRes.onRequest({
            request: request('/api/fetchRes', {
                method: 'POST',
                body: JSON.stringify({ url }),
                headers: { 'Content-Type': 'application/json' },
            }),
            env: {},
        });
    }

    it('blocks trailing-dot localhost bypasses', async () => {
        for (const target of ['http://localhost./x', 'http://127.0.0.1./x', 'http://localhost/x']) {
            const response = await postFetchRes(target, async () => assert.fail('upstream must not be fetched'));
            assert.equal(response.status, 400, target);
        }
    });

    it('requires the manage permission for token auth and strips Set-Cookie', async () => {
        const upstream = new Response('fake-image-bytes', {
            status: 200,
            headers: { 'Content-Type': 'image/png' },
        });
        upstream.headers.append('Set-Cookie', 'session=abc');
        const response = await postFetchRes('https://example.com/pic.png', async () => upstream);
        assert.equal(response.status, 200);
        assert.equal(seenAuthOptions.requiredPermission, 'manage');
        assert.equal(await response.text(), 'fake-image-bytes');
        assert.equal(response.headers.get('Content-Type'), 'image/png');
        assert.equal(response.headers.getSetCookie().length, 0);
    });

    it('rejects an upstream response whose declared size exceeds the limit', async () => {
        const response = await postFetchRes('https://example.com/big.bin', async () => new Response('x', {
            status: 200,
            headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(fetchRes.FETCH_MAX_BODY_BYTES + 1) },
        }));
        assert.equal(response.status, 413);
    });
});

describe('fix group A: P2-75 getTokenInfo is gone', () => {
    it('has no callers and is no longer exported', async () => {
        const validator = await loadFunction('functions/utils/auth/tokenValidator.js', {
            getTokenData: async () => null,
            isExpired: expiration.isExpired,
        });
        assert.equal(validator.getTokenInfo, undefined);
        assert.equal(typeof validator.validateApiToken, 'function');
    });
});
