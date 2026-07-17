// SPDX-License-Identifier: AGPL-3.0-or-later

import crypto from 'node:crypto';
import {z} from 'zod';
import * as FetchUtils from '../utils/FetchUtils';
import type {AltarAppsAuthConfig} from './AltarAppsAuthConfig';
import {ALTARAPPS_TABLETOP_PATH} from './AltarAppsAuthConfig';
import {AltarAppsAuthUnavailableError} from './AltarAppsAuthErrors';

const HandoffResponse = z
	.object({
		handoff: z.string().regex(/^aah1_[A-Za-z0-9_-]{43}$/),
		expires_at: z.iso.datetime({offset: false}),
	})
	.strict();

export interface AltarAppsHandoffRequest {
	subject: string;
	applicationId: string;
	returnTarget: string;
	pkceChallenge: string;
	authenticationMethods: ReadonlyArray<'password' | 'totp' | 'passkey' | 'recovery_code'>;
}

export interface AltarAppsHandoff {
	handoff: string;
	expiresAt: string;
}

export interface AltarAppsHandoffIssuer {
	issue(request: AltarAppsHandoffRequest): Promise<AltarAppsHandoff>;
}

type Fetch = typeof globalThis.fetch;

export class AltarAppsTabletopClient implements AltarAppsHandoffIssuer {
	constructor(
		private readonly config: Extract<AltarAppsAuthConfig, {enabled: true}>,
		private readonly fetchImpl: Fetch = globalThis.fetch,
		private readonly now: () => number = Date.now,
		private readonly nonce: () => Buffer = () => crypto.randomBytes(24),
	) {}

	async issue(request: AltarAppsHandoffRequest): Promise<AltarAppsHandoff> {
		const body = JSON.stringify({
			environment: this.config.environment,
			subject: request.subject,
			application_id: request.applicationId,
			return_target: request.returnTarget,
			pkce_challenge: request.pkceChallenge,
			authentication_methods: request.authenticationMethods,
		});
		const timestamp = Math.floor(this.now() / 1000).toString();
		const nonce = this.nonce();
		if (nonce.length !== 24) {
			throw new AltarAppsAuthUnavailableError();
		}
		const encodedNonce = nonce.toString('base64url');
		const bodyDigest = crypto.createHash('sha256').update(body).digest('base64url');
		const canonical = [
			'altarapps-verified-identity-v1',
			this.config.serviceId,
			this.config.audience,
			'POST',
			ALTARAPPS_TABLETOP_PATH,
			this.config.keyId,
			timestamp,
			encodedNonce,
			bodyDigest,
		].join('\n');
		const signature = crypto.createHmac('sha256', this.config.serviceKey).update(canonical).digest('base64url');
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
		try {
			const response = await this.fetchImpl(this.config.tabletopUrl, {
				method: 'POST',
				redirect: 'error',
				signal: controller.signal,
				headers: {
					'Content-Type': 'application/json',
					'X-Altar-Key-Id': this.config.keyId,
					'X-Altar-Timestamp': timestamp,
					'X-Altar-Nonce': encodedNonce,
					'X-Altar-Signature': signature,
				},
				body,
			});
			if (response.status !== 201 || response.headers.get('content-type') !== 'application/json') {
				await response.body?.cancel().catch(() => {});
				throw new AltarAppsAuthUnavailableError();
			}
			const raw = await FetchUtils.streamToStringWithLimit(response.body, {
				maxBytes: 8 * 1024,
				headers: response.headers,
				description: 'AltarApps Tabletop handoff response',
				signal: controller.signal,
			});
			const parsed = HandoffResponse.safeParse(JSON.parse(raw));
			if (!parsed.success) {
				throw new AltarAppsAuthUnavailableError();
			}
			const expiresAt = Date.parse(parsed.data.expires_at);
			const now = this.now();
			if (!Number.isFinite(expiresAt) || expiresAt <= now || expiresAt > now + 5 * 60 * 1000) {
				throw new AltarAppsAuthUnavailableError();
			}
			return {handoff: parsed.data.handoff, expiresAt: parsed.data.expires_at};
		} catch (error) {
			if (error instanceof AltarAppsAuthUnavailableError) {
				throw error;
			}
			throw new AltarAppsAuthUnavailableError();
		} finally {
			clearTimeout(timeout);
		}
	}
}
