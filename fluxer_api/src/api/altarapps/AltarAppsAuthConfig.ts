// SPDX-License-Identifier: AGPL-3.0-or-later

import fs from 'node:fs';
import path from 'node:path';

export const ALTARAPPS_TABLETOP_PATH = '/internal/v1/auth/verified-identity-handoffs';
export const ALTARAPPS_CHAT_ACCESS_PATH = '/internal/altarapps/v1/chat/access-tokens';
export const ALTARAPPS_CHAT_TOPOLOGY_PATH = '/internal/altarapps/v1/chat/topology';

export interface AltarAppsAuthBinding {
	applicationId: string;
	returnTarget: string;
}

export type AltarAppsAuthConfig =
	| {enabled: false}
	| {
			enabled: true;
			environment: 'test-demo';
			tabletopUrl: string;
			serviceId: 'fluxer';
			audience: 'tabletop-api';
			keyId: string;
			serviceKey: Buffer;
			allowedBindings: ReadonlyMap<string, ReadonlySet<string>>;
			chatApplicationId?: string;
			chatApiOrigin?: string;
			chatGatewayOrigin?: string;
			timeoutMs: number;
	  };

type SecretReader = (filePath: string) => string;

export function loadAltarAppsAuthConfig(
	env: NodeJS.ProcessEnv,
	readSecret: SecretReader = readProtectedSecret,
): AltarAppsAuthConfig {
	const enabled = env.ALTARAPPS_AUTH_ENABLED;
	if (enabled === undefined || enabled === '' || enabled === 'false') {
		return {enabled: false};
	}
	if (enabled !== 'true') {
		throw new Error('ALTARAPPS_AUTH_ENABLED must be true or false');
	}
	if (env.ALTARAPPS_AUTH_ENVIRONMENT !== 'test-demo') {
		throw new Error('AltarApps authentication is restricted to test-demo');
	}
	const tabletopUrl = validateTabletopUrl(env.ALTARAPPS_TABLETOP_URL);
	const keyId = env.ALTARAPPS_SERVICE_KEY_ID ?? '';
	if (!/^[a-z][a-z0-9_-]{0,63}$/.test(keyId)) {
		throw new Error('ALTARAPPS_SERVICE_KEY_ID is invalid');
	}
	const keyFile = env.ALTARAPPS_SERVICE_KEY_FILE ?? '';
	if (!path.isAbsolute(keyFile) || keyFile.length > 4096) {
		throw new Error('ALTARAPPS_SERVICE_KEY_FILE must be an absolute path');
	}
	const encodedKey = readSecret(keyFile);
	const serviceKey = Buffer.from(encodedKey, 'base64url');
	if (serviceKey.length !== 32 || serviceKey.toString('base64url') !== encodedKey) {
		throw new Error('ALTARAPPS_SERVICE_KEY_FILE does not contain a canonical 32-byte key');
	}
	const chatApplicationId = env.ALTARAPPS_CHAT_APPLICATION_ID ?? '';
	if (!/^[1-9][0-9]{0,19}$/.test(chatApplicationId)) {
		throw new Error('ALTARAPPS_CHAT_APPLICATION_ID is invalid');
	}
	return {
		enabled: true,
		environment: 'test-demo',
		tabletopUrl,
		serviceId: 'fluxer',
		audience: 'tabletop-api',
		keyId,
		serviceKey,
		allowedBindings: parseAllowedBindings(env.ALTARAPPS_ALLOWED_BINDINGS),
		chatApplicationId,
		chatApiOrigin: validatePublicOrigin(env.ALTARAPPS_CHAT_API_ORIGIN, '/api'),
		chatGatewayOrigin: validatePublicOrigin(env.ALTARAPPS_CHAT_GATEWAY_ORIGIN, '/gateway', 'wss:'),
		timeoutMs: 2000,
	};
}

function validatePublicOrigin(raw: string | undefined, requiredPath: string, protocol = 'https:'): string {
	if (!raw || raw !== raw.trim() || raw.length > 2048) {
		throw new Error('AltarApps chat origin is required');
	}
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error('AltarApps chat origin is invalid');
	}
	if (
		parsed.protocol !== protocol ||
		!parsed.hostname ||
		parsed.username !== '' ||
		parsed.password !== '' ||
		parsed.port !== '' ||
		parsed.pathname !== requiredPath ||
		parsed.search !== '' ||
		parsed.hash !== ''
	) {
		throw new Error('AltarApps chat origin is invalid');
	}
	return parsed.toString().replace(/\/$/, '');
}

export function bindingAllowed(config: AltarAppsAuthConfig, binding: AltarAppsAuthBinding): boolean {
	return config.enabled && config.allowedBindings.get(binding.applicationId)?.has(binding.returnTarget) === true;
}

function validateTabletopUrl(raw: string | undefined): string {
	if (!raw || raw !== raw.trim() || raw.length > 2048) {
		throw new Error('ALTARAPPS_TABLETOP_URL is required');
	}
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		throw new Error('ALTARAPPS_TABLETOP_URL is invalid');
	}
	if (
		(parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
		!parsed.hostname ||
		parsed.username !== '' ||
		parsed.password !== '' ||
		parsed.pathname !== ALTARAPPS_TABLETOP_PATH ||
		parsed.search !== '' ||
		parsed.hash !== ''
	) {
		throw new Error('ALTARAPPS_TABLETOP_URL must name the exact private v1 route');
	}
	return parsed.toString();
}

function parseAllowedBindings(raw: string | undefined): ReadonlyMap<string, ReadonlySet<string>> {
	if (!raw || raw !== raw.trim() || raw.length > 16 * 1024) {
		throw new Error('ALTARAPPS_ALLOWED_BINDINGS is required');
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw new Error('ALTARAPPS_ALLOWED_BINDINGS must be JSON');
	}
	if (!isRecord(parsed)) {
		throw new Error('ALTARAPPS_ALLOWED_BINDINGS must be an object');
	}
	const entries = Object.entries(parsed);
	if (entries.length === 0 || entries.length > 16) {
		throw new Error('ALTARAPPS_ALLOWED_BINDINGS has an invalid application count');
	}
	const bindings = new Map<string, ReadonlySet<string>>();
	for (const [applicationId, targets] of entries) {
		if (
			!/^[a-z][a-z0-9_-]{0,63}$/.test(applicationId) ||
			!Array.isArray(targets) ||
			targets.length === 0 ||
			targets.length > 16
		) {
			throw new Error('ALTARAPPS_ALLOWED_BINDINGS has an invalid application');
		}
		const validated = new Set<string>();
		for (const target of targets) {
			if (typeof target !== 'string' || !validReturnTarget(target) || validated.has(target)) {
				throw new Error('ALTARAPPS_ALLOWED_BINDINGS has an invalid return target');
			}
			validated.add(target);
		}
		bindings.set(applicationId, validated);
	}
	return bindings;
}

function validReturnTarget(raw: string): boolean {
	if (!raw || raw !== raw.trim() || raw.length > 2048 || containsControlCharacter(raw)) {
		return false;
	}
	try {
		const parsed = new URL(raw);
		return (
			parsed.protocol === 'https:' &&
			parsed.username === '' &&
			parsed.password === '' &&
			parsed.search === '' &&
			parsed.hash === ''
		);
	} catch {
		return false;
	}
}

function containsControlCharacter(raw: string): boolean {
	for (let index = 0; index < raw.length; index++) {
		const code = raw.charCodeAt(index);
		if (code <= 0x1f || code === 0x7f) return true;
	}
	return false;
}

function readProtectedSecret(filePath: string): string {
	const info = fs.lstatSync(filePath);
	if (!info.isFile() || info.isSymbolicLink() || info.size <= 0 || info.size > 4096) {
		throw new Error('ALTARAPPS_SERVICE_KEY_FILE is not a protected regular file');
	}
	if (process.platform !== 'win32' && (info.mode & 0o022) !== 0) {
		throw new Error('ALTARAPPS_SERVICE_KEY_FILE is writable by another account');
	}
	const raw = fs.readFileSync(filePath, 'utf8').replace(/\r?\n$/, '');
	if (!raw || raw !== raw.trim() || /[\r\n\0]/.test(raw)) {
		throw new Error('ALTARAPPS_SERVICE_KEY_FILE contains an invalid value');
	}
	return raw;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === 'object' && !Array.isArray(value);
}
