// SPDX-License-Identifier: AGPL-3.0-or-later

import path from 'node:path';
import {describe, expect, test, vi} from 'vitest';
import {bindingAllowed, loadAltarAppsAuthConfig} from '../AltarAppsAuthConfig';

const KEY = Buffer.alloc(32, 0x5a).toString('base64url');

function validEnv(): NodeJS.ProcessEnv {
	return {
		ALTARAPPS_AUTH_ENABLED: 'true',
		ALTARAPPS_AUTH_ENVIRONMENT: 'test-demo',
		ALTARAPPS_TABLETOP_URL: 'http://tabletop:8080/internal/v1/auth/verified-identity-handoffs',
		ALTARAPPS_SERVICE_KEY_ID: 'fluxer-test-1',
		ALTARAPPS_SERVICE_KEY_FILE: path.resolve('altarapps-test-secret.key'),
		ALTARAPPS_ALLOWED_BINDINGS: JSON.stringify({
			player_app: ['https://tests.abysstail.art/auth/callback'],
		}),
	};
}

describe('AltarAppsAuthConfig', () => {
	test('stays disabled unless explicitly enabled', () => {
		const readSecret = vi.fn(() => KEY);

		expect(loadAltarAppsAuthConfig({}, readSecret)).toEqual({enabled: false});
		expect(readSecret).not.toHaveBeenCalled();
	});

	test('loads the Test/Demo service boundary and exact bindings', () => {
		const readSecret = vi.fn(() => KEY);
		const config = loadAltarAppsAuthConfig(validEnv(), readSecret);

		expect(config.enabled).toBe(true);
		if (!config.enabled) throw new Error('expected enabled config');
		expect(config.serviceKey).toEqual(Buffer.alloc(32, 0x5a));
		expect(readSecret).toHaveBeenCalledOnce();
		expect(
			bindingAllowed(config, {
				applicationId: 'player_app',
				returnTarget: 'https://tests.abysstail.art/auth/callback',
			}),
		).toBe(true);
		expect(
			bindingAllowed(config, {
				applicationId: 'master_hub',
				returnTarget: 'https://tests.abysstail.art/auth/callback',
			}),
		).toBe(false);
	});

	test.each([
		['Production environment', {ALTARAPPS_AUTH_ENVIRONMENT: 'production'}],
		['public route', {ALTARAPPS_TABLETOP_URL: 'https://tests.abysstail.art/'}],
		['relative secret path', {ALTARAPPS_SERVICE_KEY_FILE: 'altarapps.key'}],
		['non-canonical key', {}],
		[
			'return target with query',
			{
				ALTARAPPS_ALLOWED_BINDINGS: JSON.stringify({player_app: ['https://tests.abysstail.art/auth/callback?next=x']}),
			},
		],
	])('rejects %s configuration', (_name, overrides) => {
		const env = {...validEnv(), ...overrides};
		const secret = _name === 'non-canonical key' ? `${KEY}=` : KEY;

		expect(() => loadAltarAppsAuthConfig(env, () => secret)).toThrow();
	});
});
