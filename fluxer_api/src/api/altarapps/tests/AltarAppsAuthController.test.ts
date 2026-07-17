// SPDX-License-Identifier: AGPL-3.0-or-later

import {Hono} from 'hono';
import {describe, expect, test, vi} from 'vitest';
import type {SsoService} from '../../auth/services/SsoService';
import type {HonoEnv} from '../../types/HonoEnv';
import {AltarAppsAuthController} from '../AltarAppsAuthController';
import {AltarAppsAuthRejectedError} from '../AltarAppsAuthErrors';
import type {AltarAppsAuthService} from '../AltarAppsAuthService';

const PASSWORD_BODY = {
	environment: 'test-demo',
	application_id: 'player_app',
	return_target: 'https://tests.abysstail.art/auth/callback',
	pkce_challenge: 'A'.repeat(43),
	email: 'player@example.com',
	password: 'correct horse battery staple',
};

function appWith(service: AltarAppsAuthService | null) {
	const app = new Hono<HonoEnv>();
	app.use('*', async (ctx, next) => {
		ctx.set('altarAppsAuthService', service);
		ctx.set('ssoService', {isEnforced: async () => false} as SsoService);
		return await next();
	});
	AltarAppsAuthController(app);
	return app;
}

describe('AltarAppsAuthController', () => {
	test('looks absent and remains non-cacheable when the adapter is disabled', async () => {
		const response = await appWith(null).request('/altarapps/v1/auth/password', {
			method: 'POST',
			headers: {'content-type': 'application/json'},
			body: '{}',
		});

		expect(response.status).toBe(404);
		expect(response.headers.get('cache-control')).toBe('no-store');
		expect(await response.json()).toEqual({code: 'not_found'});
	});

	test('returns only the native handoff response with secure headers', async () => {
		const passwordLogin = vi.fn(async () => ({
			status: 'complete' as const,
			handoff: `aah1_${'H'.repeat(43)}`,
			expires_at: '2026-07-17T18:02:00Z',
		}));
		const service = {passwordLogin} as unknown as AltarAppsAuthService;
		const response = await appWith(service).request('/altarapps/v1/auth/password', {
			method: 'POST',
			headers: {'content-type': 'application/json'},
			body: JSON.stringify(PASSWORD_BODY),
		});

		expect(response.status).toBe(200);
		expect(response.headers.get('cache-control')).toBe('no-store');
		expect(response.headers.get('referrer-policy')).toBe('no-referrer');
		expect(response.headers.get('x-content-type-options')).toBe('nosniff');
		expect(await response.json()).toEqual({
			status: 'complete',
			handoff: `aah1_${'H'.repeat(43)}`,
			expires_at: '2026-07-17T18:02:00Z',
		});
		expect(passwordLogin).toHaveBeenCalledOnce();
	});

	test('uses the same public error for a rejected TOTP transaction', async () => {
		const completeTotp = vi.fn(async () => {
			throw new AltarAppsAuthRejectedError();
		});
		const service = {completeTotp} as unknown as AltarAppsAuthService;
		const response = await appWith(service).request('/altarapps/v1/auth/mfa/totp', {
			method: 'POST',
			headers: {'content-type': 'application/json'},
			body: JSON.stringify({transaction: `aat1_${'T'.repeat(64)}`, code: '123456'}),
		});

		expect(response.status).toBe(401);
		expect(response.headers.get('cache-control')).toBe('no-store');
		expect(await response.json()).toEqual({code: 'invalid_credentials'});
	});
});
