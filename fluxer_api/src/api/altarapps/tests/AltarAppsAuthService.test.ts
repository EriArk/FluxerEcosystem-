// SPDX-License-Identifier: AGPL-3.0-or-later

import {type UserAuthenticatorType, UserAuthenticatorTypes} from '@fluxer/constants/src/UserConstants';
import {InMemoryProvider} from '@pkgs/cache/src/providers/InMemoryProvider';
import {afterEach, describe, expect, test, vi} from 'vitest';
import type {ApiContext} from '../../ApiContext';
import type {LoginDependencies} from '../../auth/AuthLogin';
import * as AuthLogin from '../../auth/AuthLogin';
import * as AuthPassword from '../../auth/AuthPassword';
import * as AuthSession from '../../auth/AuthSession';
import * as AuthUtility from '../../auth/AuthUtility';
import type {User} from '../../models/User';
import type {AltarAppsAuthConfig} from '../AltarAppsAuthConfig';
import {AltarAppsAuthRejectedError, AltarAppsAuthUnavailableError} from '../AltarAppsAuthErrors';
import type {AltarAppsPasswordLoginRequest} from '../AltarAppsAuthSchemas';
import {AltarAppsAuthService} from '../AltarAppsAuthService';
import type {AltarAppsHandoffIssuer} from '../AltarAppsTabletopClient';

const HANDOFF = `aah1_${'H'.repeat(43)}`;
const RETURN_TARGET = 'https://tests.abysstail.art/auth/callback';

function config(): Extract<AltarAppsAuthConfig, {enabled: true}> {
	return {
		enabled: true,
		environment: 'test-demo',
		tabletopUrl: 'http://tabletop:8080/internal/v1/auth/verified-identity-handoffs',
		serviceId: 'fluxer',
		audience: 'tabletop-api',
		keyId: 'fluxer-test-1',
		serviceKey: Buffer.alloc(32),
		allowedBindings: new Map([['player_app', new Set([RETURN_TARGET])]]),
		chatOwnerUserId: '123456789012345679',
		timeoutMs: 2000,
	};
}

function request(): AltarAppsPasswordLoginRequest {
	return {
		environment: 'test-demo',
		application_id: 'player_app',
		return_target: RETURN_TARGET,
		pkce_challenge: 'A'.repeat(43),
		email: 'player@example.com',
		password: 'correct horse battery staple',
	};
}

function user(authenticatorTypes: ReadonlySet<UserAuthenticatorType> = new Set()): User {
	return {
		id: 123456789012345678n,
		authenticatorTypes,
	} as unknown as User;
}

function setup() {
	const cache = new InMemoryProvider();
	const ctx = {services: {cache}} as unknown as ApiContext;
	const dependencies = {} as LoginDependencies;
	const issue = vi.fn(async () => ({handoff: HANDOFF, expiresAt: '2026-07-17T18:02:00Z'}));
	const handoffs: AltarAppsHandoffIssuer = {issue};
	const service = new AltarAppsAuthService(ctx, dependencies, config(), handoffs);
	return {cache, ctx, dependencies, issue, service};
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe('AltarAppsAuthService', () => {
	test('returns only the Tabletop handoff and never creates a Fluxer session', async () => {
		const {issue, service} = setup();
		const verifyPassword = vi.spyOn(AuthLogin, 'verifyPasswordLogin').mockResolvedValue(user());
		const createSession = vi.spyOn(AuthSession, 'createAuthSession');

		const result = await service.passwordLogin(request(), new Request('https://identity-tests.abysstail.art'));

		expect(result).toEqual({status: 'complete', handoff: HANDOFF, expires_at: '2026-07-17T18:02:00Z'});
		expect(createSession).not.toHaveBeenCalled();
		expect(verifyPassword).toHaveBeenCalledWith(
			expect.anything(),
			expect.anything(),
			expect.objectContaining({
				includeIdentityInLogs: false,
				allowDevRateLimitBypass: false,
			}),
		);
		expect(issue).toHaveBeenCalledExactlyOnceWith({
			subject: '123456789012345678',
			applicationId: 'player_app',
			returnTarget: RETURN_TARGET,
			pkceChallenge: 'A'.repeat(43),
			authenticationMethods: ['password'],
		});
		const publicResult = JSON.stringify(result);
		expect(publicResult).not.toContain('123456789012345678');
		expect(publicResult).not.toContain('fluxer');
		expect(publicResult).not.toContain('player@example.com');
	});

	test('rejects an unapproved application binding before password verification', async () => {
		const {issue, service} = setup();
		const verify = vi.spyOn(AuthLogin, 'verifyPasswordLogin');
		const invalid = {...request(), application_id: 'master_hub'};

		await expect(
			service.passwordLogin(invalid, new Request('https://identity-tests.abysstail.art')),
		).rejects.toBeInstanceOf(AltarAppsAuthRejectedError);
		expect(verify).not.toHaveBeenCalled();
		expect(issue).not.toHaveBeenCalled();
	});

	test('uses an opaque one-use TOTP transaction without backup codes', async () => {
		const {cache, issue, service} = setup();
		const mfaUser = user(new Set([UserAuthenticatorTypes.TOTP]));
		vi.spyOn(AuthLogin, 'verifyPasswordLogin').mockResolvedValue(mfaUser);
		vi.spyOn(AuthLogin, 'getLoginMfaAvailability').mockResolvedValue({hasTotp: true, hasWebauthn: false});
		vi.spyOn(AuthUtility, 'generateSecureToken').mockResolvedValue('T'.repeat(64));
		const cacheSet = vi.spyOn(cache, 'set');
		const verifyTotp = vi.spyOn(AuthLogin, 'verifyMfaTotpForUser').mockResolvedValue(mfaUser);

		const started = await service.passwordLogin(request(), new Request('https://identity-tests.abysstail.art'));
		expect(started).toEqual({status: 'mfa_required', transaction: `aat1_${'T'.repeat(64)}`, methods: ['totp']});
		expect(JSON.stringify(started)).not.toContain('123456789012345678');
		expect(cacheSet.mock.calls[0]?.[0]).not.toContain(`aat1_${'T'.repeat(64)}`);

		const completed = await service.completeTotp(
			{transaction: `aat1_${'T'.repeat(64)}`, code: '123456'},
			new Request('https://identity-tests.abysstail.art'),
		);
		expect(completed).toEqual({status: 'complete', handoff: HANDOFF, expires_at: '2026-07-17T18:02:00Z'});
		expect(verifyTotp).toHaveBeenCalledWith(
			expect.anything(),
			expect.anything(),
			expect.objectContaining({
				userId: '123456789012345678',
				code: '123456',
				allowBackup: false,
			}),
		);
		expect(issue).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({
				authenticationMethods: ['password', 'totp'],
			}),
		);

		await expect(
			service.completeTotp(
				{transaction: `aat1_${'T'.repeat(64)}`, code: '123456'},
				new Request('https://identity-tests.abysstail.art'),
			),
		).rejects.toBeInstanceOf(AltarAppsAuthRejectedError);
		expect(issue).toHaveBeenCalledTimes(1);
	});

	test('keeps the TOTP transaction retryable after a technical verification failure', async () => {
		const {service} = setup();
		const mfaUser = user(new Set([UserAuthenticatorTypes.TOTP]));
		vi.spyOn(AuthLogin, 'verifyPasswordLogin').mockResolvedValue(mfaUser);
		vi.spyOn(AuthLogin, 'getLoginMfaAvailability').mockResolvedValue({hasTotp: true, hasWebauthn: false});
		vi.spyOn(AuthUtility, 'generateSecureToken').mockResolvedValue('T'.repeat(64));
		const verifyTotp = vi
			.spyOn(AuthLogin, 'verifyMfaTotpForUser')
			.mockRejectedValueOnce(new Error('temporary dependency failure'))
			.mockResolvedValueOnce(mfaUser);
		await service.passwordLogin(request(), new Request('https://identity-tests.abysstail.art'));

		await expect(
			service.completeTotp(
				{transaction: `aat1_${'T'.repeat(64)}`, code: '123456'},
				new Request('https://identity-tests.abysstail.art'),
			),
		).rejects.toBeInstanceOf(AltarAppsAuthUnavailableError);
		await expect(
			service.completeTotp(
				{transaction: `aat1_${'T'.repeat(64)}`, code: '123456'},
				new Request('https://identity-tests.abysstail.art'),
			),
		).resolves.toMatchObject({status: 'complete', handoff: HANDOFF});
		expect(verifyTotp).toHaveBeenCalledTimes(2);
	});

	test('requests recovery generically through Fluxer without creating a session', async () => {
		const {service} = setup();
		const forgotPassword = vi.spyOn(AuthPassword, 'forgotPassword').mockResolvedValue();
		const createSession = vi.spyOn(AuthSession, 'createAuthSession');

		await service.requestPasswordRecovery(
			{environment: 'test-demo', email: 'player@example.com'},
			new Request('https://identity-tests.abysstail.art'),
		);

		expect(forgotPassword).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({data: {email: 'player@example.com'}}),
		);
		expect(createSession).not.toHaveBeenCalled();
	});

	test('completes recovery without returning a Fluxer session', async () => {
		const {issue, service} = setup();
		const resetPassword = vi.spyOn(AuthPassword, 'resetPasswordWithoutSession').mockResolvedValue(user());
		const createSession = vi.spyOn(AuthSession, 'createAuthSession');
		const data = {
			environment: 'test-demo' as const,
			application_id: 'player_app',
			return_target: RETURN_TARGET,
			pkce_challenge: 'A'.repeat(43),
			token: 'R'.repeat(64),
			password: 'new correct horse battery staple',
		};

		const result = await service.completePasswordRecovery(data);

		expect(result).toEqual({status: 'complete', handoff: HANDOFF, expires_at: '2026-07-17T18:02:00Z'});
		expect(resetPassword).toHaveBeenCalledWith(expect.anything(), {
			token: 'R'.repeat(64),
			password: 'new correct horse battery staple',
		});
		expect(createSession).not.toHaveBeenCalled();
		expect(issue).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({authenticationMethods: ['recovery_code']}));
	});

	test('preserves TOTP as a required step after recovery', async () => {
		const {issue, service} = setup();
		const mfaUser = user(new Set([UserAuthenticatorTypes.TOTP]));
		vi.spyOn(AuthPassword, 'resetPasswordWithoutSession').mockResolvedValue(mfaUser);
		vi.spyOn(AuthLogin, 'getLoginMfaAvailability').mockResolvedValue({hasTotp: true, hasWebauthn: false});
		vi.spyOn(AuthUtility, 'generateSecureToken').mockResolvedValue('T'.repeat(64));
		vi.spyOn(AuthLogin, 'verifyMfaTotpForUser').mockResolvedValue(mfaUser);

		const started = await service.completePasswordRecovery({
			environment: 'test-demo',
			application_id: 'player_app',
			return_target: RETURN_TARGET,
			pkce_challenge: 'A'.repeat(43),
			token: 'R'.repeat(64),
			password: 'new correct horse battery staple',
		});
		expect(started).toEqual({status: 'mfa_required', transaction: `aat1_${'T'.repeat(64)}`, methods: ['totp']});

		await service.completeTotp(
			{transaction: `aat1_${'T'.repeat(64)}`, code: '123456'},
			new Request('https://identity-tests.abysstail.art'),
		);
		expect(issue).toHaveBeenCalledExactlyOnceWith(
			expect.objectContaining({authenticationMethods: ['recovery_code', 'totp']}),
		);
	});

	test('does not downgrade a WebAuthn-only account to password-only access', async () => {
		const {issue, service} = setup();
		const webauthnUser = user(new Set([UserAuthenticatorTypes.WEBAUTHN]));
		vi.spyOn(AuthLogin, 'verifyPasswordLogin').mockResolvedValue(webauthnUser);
		vi.spyOn(AuthLogin, 'getLoginMfaAvailability').mockResolvedValue({hasTotp: false, hasWebauthn: true});

		await expect(
			service.passwordLogin(request(), new Request('https://identity-tests.abysstail.art')),
		).rejects.toBeInstanceOf(AltarAppsAuthUnavailableError);
		expect(issue).not.toHaveBeenCalled();
	});
});
