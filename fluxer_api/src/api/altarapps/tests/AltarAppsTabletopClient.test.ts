// SPDX-License-Identifier: AGPL-3.0-or-later

import crypto from 'node:crypto';
import {describe, expect, test, vi} from 'vitest';
import type {AltarAppsAuthConfig} from '../AltarAppsAuthConfig';
import {ALTARAPPS_TABLETOP_PATH} from '../AltarAppsAuthConfig';
import {AltarAppsAuthUnavailableError} from '../AltarAppsAuthErrors';
import {AltarAppsTabletopClient} from '../AltarAppsTabletopClient';

const NOW = Date.parse('2026-07-17T18:00:00Z');
const HANDOFF = `aah1_${'H'.repeat(43)}`;

function config(): Extract<AltarAppsAuthConfig, {enabled: true}> {
	return {
		enabled: true,
		environment: 'test-demo',
		tabletopUrl: `http://tabletop:8080${ALTARAPPS_TABLETOP_PATH}`,
		serviceId: 'fluxer',
		audience: 'tabletop-api',
		keyId: 'fluxer-test-1',
		serviceKey: Buffer.alloc(32, 0x5a),
		allowedBindings: new Map(),
		timeoutMs: 2000,
	};
}

describe('AltarAppsTabletopClient', () => {
	test('signs the exact private contract and returns only a one-use handoff', async () => {
		const nonce = Buffer.alloc(24, 0xa5);
		const fetchMock = vi.fn(
			async (_input: Parameters<typeof globalThis.fetch>[0], _init?: Parameters<typeof globalThis.fetch>[1]) =>
				new Response(
					JSON.stringify({
						handoff: HANDOFF,
						expires_at: '2026-07-17T18:02:00Z',
					}),
					{
						status: 201,
						headers: {'content-type': 'application/json'},
					},
				),
		);
		const client = new AltarAppsTabletopClient(
			config(),
			fetchMock as unknown as typeof globalThis.fetch,
			() => NOW,
			() => nonce,
		);

		const result = await client.issue({
			subject: '123456789012345678',
			applicationId: 'player_app',
			returnTarget: 'https://tests.abysstail.art/auth/callback',
			pkceChallenge: 'A'.repeat(43),
			authenticationMethods: ['password'],
		});

		expect(result).toEqual({handoff: HANDOFF, expiresAt: '2026-07-17T18:02:00Z'});
		expect(fetchMock).toHaveBeenCalledOnce();
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe(`http://tabletop:8080${ALTARAPPS_TABLETOP_PATH}`);
		expect(init?.method).toBe('POST');
		expect(init?.redirect).toBe('error');
		const body = init?.body?.toString() ?? '';
		expect(JSON.parse(body)).toEqual({
			environment: 'test-demo',
			subject: '123456789012345678',
			application_id: 'player_app',
			return_target: 'https://tests.abysstail.art/auth/callback',
			pkce_challenge: 'A'.repeat(43),
			authentication_methods: ['password'],
		});
		expect(body).not.toContain('email');
		expect(body).not.toContain('password_hash');
		expect(body).not.toContain('token');

		const headers = new Headers(init?.headers);
		const timestamp = Math.floor(NOW / 1000).toString();
		const encodedNonce = nonce.toString('base64url');
		const bodyDigest = crypto.createHash('sha256').update(body).digest('base64url');
		const canonical = [
			'altarapps-verified-identity-v1',
			'fluxer',
			'tabletop-api',
			'POST',
			ALTARAPPS_TABLETOP_PATH,
			'fluxer-test-1',
			timestamp,
			encodedNonce,
			bodyDigest,
		].join('\n');
		const signature = crypto.createHmac('sha256', Buffer.alloc(32, 0x5a)).update(canonical).digest('base64url');
		expect(headers.get('content-type')).toBe('application/json');
		expect(headers.get('x-altar-key-id')).toBe('fluxer-test-1');
		expect(headers.get('x-altar-timestamp')).toBe(timestamp);
		expect(headers.get('x-altar-nonce')).toBe(encodedNonce);
		expect(headers.get('x-altar-signature')).toBe(signature);
	});

	test.each([
		['wrong status', new Response('{}', {status: 200, headers: {'content-type': 'application/json'}})],
		['wrong content type', new Response('{}', {status: 201, headers: {'content-type': 'text/plain'}})],
		[
			'unexpected response member',
			new Response(
				JSON.stringify({
					handoff: HANDOFF,
					expires_at: '2026-07-17T18:02:00Z',
					subject: '123',
				}),
				{status: 201, headers: {'content-type': 'application/json'}},
			),
		],
		[
			'expired handoff',
			new Response(
				JSON.stringify({
					handoff: HANDOFF,
					expires_at: '2026-07-17T17:59:59Z',
				}),
				{status: 201, headers: {'content-type': 'application/json'}},
			),
		],
	])('rejects a %s response', async (_name, response) => {
		const client = new AltarAppsTabletopClient(
			config(),
			vi.fn(async () => response) as unknown as typeof globalThis.fetch,
			() => NOW,
			() => Buffer.alloc(24),
		);

		await expect(
			client.issue({
				subject: '123',
				applicationId: 'player_app',
				returnTarget: 'https://tests.abysstail.art/auth/callback',
				pkceChallenge: 'A'.repeat(43),
				authenticationMethods: ['password'],
			}),
		).rejects.toBeInstanceOf(AltarAppsAuthUnavailableError);
	});
});
