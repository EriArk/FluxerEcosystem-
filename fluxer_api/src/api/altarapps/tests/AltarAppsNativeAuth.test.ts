// SPDX-License-Identifier: AGPL-3.0-or-later

import {verifyPasswordLogin} from '@app/api/auth/AuthLogin';
import {resetPasswordWithoutSession} from '@app/api/auth/AuthPassword';
import {registerAltarApps} from '@app/api/auth/AuthRegistration';
import {
	createTestAccount,
	createUniqueEmail,
	createUniqueUsername,
	findLastTestEmail,
	listTestEmails,
} from '@app/api/auth/tests/AuthTestUtils';
import {createUserID} from '@app/api/BrandedTypes';
import {createApiContext} from '@app/api/CreateApiContext';
import {
	getDiscriminatorService,
	getInstanceConfigRepository,
	getKVActivityTracker,
	getUserRepository,
} from '@app/api/middleware/ServiceSingletons';
import {type ApiTestHarness, createApiTestHarness} from '@app/api/test/ApiTestHarness';
import {createBuilder, createBuilderWithoutAuth} from '@app/api/test/TestRequestBuilder';
import {RegisterRequest} from '@fluxer/schema/src/domains/auth/AuthSchemas';
import {afterAll, beforeAll, beforeEach, describe, expect, it} from 'vitest';

describe('AltarApps native authentication after upstream upgrade', () => {
	let harness: ApiTestHarness;
	beforeAll(async () => {
		harness = await createApiTestHarness({
			registerRoutes: (routes) => {
				routes.post('/altar-test/register', async (ctx) => {
					await registerAltarApps(
						ctx.get('apiContext'),
						{
							inviteService: ctx.get('inviteService'),
							instanceConfigRepository: getInstanceConfigRepository(),
							singleCommunityService: ctx.get('singleCommunityService'),
							guildVisitService: ctx.get('guildVisitService'),
							discriminatorService: getDiscriminatorService(),
							kvActivityTracker: getKVActivityTracker(),
						},
						{
							data: RegisterRequest.parse(await ctx.req.json()),
							request: ctx.req.raw,
							requestCache: ctx.get('requestCache'),
						},
					);
					return ctx.body(null, 204);
				});
			},
		});
	});
	beforeEach(async () => {
		await harness.reset();
	});
	afterAll(async () => {
		await harness?.shutdown();
	});

	it('verifies a real password without creating a provider session and enforces throttling', async () => {
		const account = await createTestAccount(harness);
		const ctx = createApiContext();
		const userId = createUserID(BigInt(account.userId));
		const before = await ctx.services.users.listAuthSessions(userId);
		const params = {
			data: {email: account.email, password: account.password},
			request: new Request('http://localhost', {headers: {'x-forwarded-for': account.ipAddress ?? '127.0.0.1'}}),
			includeIdentityInLogs: false,
			allowDevRateLimitBypass: false,
		};
		expect((await verifyPasswordLogin(ctx, {} as never, params)).id).toBe(userId);
		expect(await ctx.services.users.listAuthSessions(userId)).toHaveLength(before.length);
		await expect(
			verifyPasswordLogin(ctx, {} as never, {...params, data: {...params.data, password: 'incorrect'}}),
		).rejects.toThrow();
		for (let i = 0; i < 12; i++) {
			await verifyPasswordLogin(ctx, {} as never, {...params, data: {...params.data, password: 'incorrect'}}).catch(
				() => {},
			);
		}
		await expect(verifyPasswordLogin(ctx, {} as never, params)).rejects.toThrow();
	});

	it('keeps public signup closed while first-party signup requires verification and creates no session', async () => {
		await getInstanceConfigRepository().setRegistrationConfig({mode: 'closed'});
		const data = {
			email: createUniqueEmail(),
			username: createUniqueUsername(),
			password: 'a-strong-password',
			date_of_birth: '2000-01-01',
			consent: true,
		};
		await createBuilderWithoutAuth(harness).post('/auth/register').body(data).expect(403).execute();
		await createBuilderWithoutAuth(harness).post('/altar-test/register').body(data).expect(204).execute();
		const user = await getUserRepository().findByEmail(data.email);
		expect(user).not.toBeNull();
		expect(user!.emailVerified).toBe(false);
		expect(await getUserRepository().listAuthSessions(user!.id)).toHaveLength(0);
		expect(
			findLastTestEmail(await listTestEmails(harness, {recipient: data.email}), 'email_verification'),
		).toBeDefined();
	});

	it('resets a password once, revokes old sessions and returns no provider session', async () => {
		const account = await createTestAccount(harness);
		await createBuilderWithoutAuth(harness).post('/auth/forgot').body({email: account.email}).expect(204).execute();
		const email = findLastTestEmail(await listTestEmails(harness, {recipient: account.email}), 'password_reset');
		const data = {token: email!.metadata.token!, password: 'another-strong-password'};
		const ctx = createApiContext();
		const user = await resetPasswordWithoutSession(ctx, data);
		expect(user.id.toString()).toBe(account.userId);
		expect(await ctx.services.users.listAuthSessions(user.id)).toHaveLength(0);
		await createBuilder(harness, account.token).get('/users/@me').expect(401).execute();
		await expect(resetPasswordWithoutSession(ctx, data)).rejects.toThrow();
	});
});
