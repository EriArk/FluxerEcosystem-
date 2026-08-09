// SPDX-License-Identifier: AGPL-3.0-or-later

import crypto from 'node:crypto';
import {FluxerError} from '@fluxer/errors/src/FluxerError';
import type {IKVProvider} from '@pkgs/kv_client/src/IKVProvider';
import {seconds} from 'itty-time';
import type {ApiContext} from '../ApiContext';
import * as AuthLogin from '../auth/AuthLogin';
import * as AuthEmail from '../auth/AuthEmail';
import * as AuthPassword from '../auth/AuthPassword';
import * as AuthRegistration from '../auth/AuthRegistration';
import * as AuthUtility from '../auth/AuthUtility';
import {createApplicationID, createUserID} from '../BrandedTypes';
import type {OAuth2AccessTokenRow} from '../database/types/OAuth2Types';
import type {RequestCache} from '../middleware/RequestCacheMiddleware';
import type {User} from '../models/User';
import {generateOAuthTokenSecret} from '../oauth/OAuthTokenSecret';
import type {IOAuth2TokenRepository} from '../oauth/repositories/IOAuth2TokenRepository';
import type {AltarAppsAuthConfig} from './AltarAppsAuthConfig';
import {ALTARAPPS_CHAT_ACCESS_PATH, bindingAllowed} from './AltarAppsAuthConfig';
import {
	AltarAppsAuthRejectedError,
	AltarAppsAuthThrottledError,
	AltarAppsAuthUnavailableError,
} from './AltarAppsAuthErrors';
import type {
	AltarAppsAuthResponse,
	AltarAppsPasswordLoginRequest,
	AltarAppsRegistrationRequest,
	AltarAppsRegistrationResendRequest,
	AltarAppsRegistrationResponse,
	AltarAppsRecoveryCompleteRequest,
	AltarAppsRecoveryRequest,
	AltarAppsTotpRequest,
} from './AltarAppsAuthSchemas';
import type {AltarAppsHandoffIssuer} from './AltarAppsTabletopClient';

const TRANSACTION_TTL = seconds('5 minutes');
const TRANSACTION_MAX_ATTEMPTS = 5;
const CHAT_ACCESS_TTL = seconds('15 minutes');
const CHAT_SIGNATURE_CLOCK_SKEW = seconds('1 minute');
const CHAT_MAXIMUM_BODY_BYTES = 8 * 1024;

interface MfaTransaction {
	version: 2;
	userId: string;
	applicationId: string;
	returnTarget: string;
	pkceChallenge: string;
	primaryMethod: 'password' | 'recovery_code';
}

interface AltarAppsBinding {
	environment: 'test-demo';
	application_id: string;
	return_target: string;
	pkce_challenge: string;
}

export class AltarAppsAuthService {
	constructor(
		private readonly ctx: ApiContext,
		private readonly loginDependencies: AuthLogin.LoginDependencies,
		private readonly config: Extract<AltarAppsAuthConfig, {enabled: true}>,
		private readonly handoffs: AltarAppsHandoffIssuer,
		private readonly nativeDependencies?: {
			registrationDependencies: AuthRegistration.RegistrationDependencies;
			oauth2Tokens: IOAuth2TokenRepository;
			kvClient: IKVProvider;
		},
	) {}

	async issueChatAccess(request: {method: string; headers: Headers; body: Buffer}): Promise<{
		access_token: string;
		token_type: 'Bearer';
		expires_in: number;
		expires_at: string;
		api_origin: string;
		gateway_origin: string;
	}> {
		const nativeDependencies = this.nativeDependencies;
		const chatApplicationId = this.config.chatApplicationId;
		const chatApiOrigin = this.config.chatApiOrigin;
		const chatGatewayOrigin = this.config.chatGatewayOrigin;
		if (!nativeDependencies || !chatApplicationId || !chatApiOrigin || !chatGatewayOrigin) {
			throw new AltarAppsAuthUnavailableError();
		}
		const rawLength = Number.parseInt(request.headers.get('content-length') ?? '0', 10);
		if (
			request.method !== 'POST' ||
			request.headers.get('content-type') !== 'application/json' ||
			(Number.isFinite(rawLength) && rawLength > CHAT_MAXIMUM_BODY_BYTES)
		) {
			throw new AltarAppsAuthRejectedError();
		}
		const body = request.body;
		if (body.length === 0 || body.length > CHAT_MAXIMUM_BODY_BYTES) {
			throw new AltarAppsAuthRejectedError();
		}
		await this.verifyChatAssertion(request.headers, body);
		let parsed: unknown;
		try {
			parsed = JSON.parse(body.toString('utf8'));
		} catch {
			throw new AltarAppsAuthRejectedError();
		}
		if (!isChatAccessBody(parsed) || parsed.environment !== this.config.environment) {
			throw new AltarAppsAuthRejectedError();
		}
		const userId = createUserID(BigInt(parsed.subject));
		const user = await this.ctx.services.users.findUnique(userId).catch(() => {
			throw new AltarAppsAuthUnavailableError();
		});
		if (!user || user.isBot || user.pendingDeletionAt !== null) {
			throw new AltarAppsAuthRejectedError();
		}
		const createdAt = new Date();
		const row: OAuth2AccessTokenRow = {
			token_: generateOAuthTokenSecret(),
			application_id: createApplicationID(BigInt(chatApplicationId)),
			user_id: userId,
			scope: new Set(['identify', 'chat']),
			created_at: createdAt,
		};
		const token = await nativeDependencies.oauth2Tokens.createAccessToken(row, CHAT_ACCESS_TTL).catch(() => {
			throw new AltarAppsAuthUnavailableError();
		});
		return {
			access_token: token.token,
			token_type: 'Bearer',
			expires_in: CHAT_ACCESS_TTL,
			expires_at: new Date(createdAt.getTime() + CHAT_ACCESS_TTL * 1000).toISOString(),
			api_origin: chatApiOrigin,
			gateway_origin: chatGatewayOrigin,
		};
	}

	private async verifyChatAssertion(headers: Headers, body: Buffer): Promise<void> {
		const keyId = headers.get('x-altar-key-id') ?? '';
		const timestamp = headers.get('x-altar-timestamp') ?? '';
		const nonce = headers.get('x-altar-nonce') ?? '';
		const signature = headers.get('x-altar-signature') ?? '';
		if (keyId !== this.config.keyId || !/^[1-9][0-9]{9}$/.test(timestamp)) {
			throw new AltarAppsAuthRejectedError();
		}
		const assertedAt = Number.parseInt(timestamp, 10);
		const now = Math.floor(Date.now() / 1000);
		if (Math.abs(now - assertedAt) > CHAT_SIGNATURE_CLOCK_SKEW) {
			throw new AltarAppsAuthRejectedError();
		}
		const decodedNonce = Buffer.from(nonce, 'base64url');
		const decodedSignature = Buffer.from(signature, 'base64url');
		if (
			decodedNonce.length !== 24 ||
			decodedNonce.toString('base64url') !== nonce ||
			decodedSignature.length !== 32 ||
			decodedSignature.toString('base64url') !== signature
		) {
			throw new AltarAppsAuthRejectedError();
		}
		const bodyDigest = crypto.createHash('sha256').update(body).digest('base64url');
		const canonical = [
			'altarapps-chat-access-v1',
			'tabletop',
			'fluxer-api',
			'POST',
			ALTARAPPS_CHAT_ACCESS_PATH,
			keyId,
			timestamp,
			nonce,
			bodyDigest,
		].join('\n');
		const expected = crypto.createHmac('sha256', this.config.serviceKey).update(canonical).digest();
		if (!crypto.timingSafeEqual(decodedSignature, expected)) {
			throw new AltarAppsAuthRejectedError();
		}
		const replayKey = `altarapps-chat-access-replay:${crypto.createHash('sha256').update(`${keyId}\0${nonce}`).digest('base64url')}`;
		const claimed = await this.nativeDependencies?.kvClient.setnx(replayKey, '1', CHAT_SIGNATURE_CLOCK_SKEW * 2);
		if (!claimed) {
			throw new AltarAppsAuthRejectedError();
		}
	}

	async register(
		data: AltarAppsRegistrationRequest,
		request: Request,
		requestCache: RequestCache,
	): Promise<AltarAppsRegistrationResponse> {
		this.assertBinding(data);
		const registrationDependencies = this.nativeDependencies?.registrationDependencies;
		if (!registrationDependencies) {
			throw new AltarAppsAuthUnavailableError();
		}
		try {
			await AuthRegistration.register(this.ctx, registrationDependencies, {
				data: {
					email: data.email,
					global_name: data.display_name,
					password: data.password,
					consent: false,
					invite_code: null,
					registration_url_code: null,
					theme: 'system',
				},
				request,
				requestCache,
				source: 'altarapps-native',
			});
			return {status: 'verification_required', email: data.email};
		} catch (error) {
			throw mapAuthError(error);
		}
	}

	async resendRegistrationEmail(data: AltarAppsRegistrationResendRequest): Promise<void> {
		if (data.environment !== this.config.environment || !this.nativeDependencies) {
			throw new AltarAppsAuthRejectedError();
		}
		try {
			const user = await this.ctx.services.users.findByEmail(data.email);
			if (!user || user.emailVerified || user.pendingDeletionAt !== null) {
				return;
			}
			await AuthEmail.resendVerificationEmail(this.ctx, user);
		} catch (error) {
			throw mapAuthError(error);
		}
	}

	async passwordLogin(data: AltarAppsPasswordLoginRequest, request: Request): Promise<AltarAppsAuthResponse> {
		this.assertBinding(data);
		let user: User;
		try {
			user = await AuthLogin.verifyPasswordLogin(this.ctx, this.loginDependencies, {
				data: {email: data.email, password: data.password, invite_code: null},
				request,
				includeIdentityInLogs: false,
				allowDevRateLimitBypass: false,
			});
		} catch (error) {
			throw mapAuthError(error);
		}

		if (AuthLogin.requiresLoginMfa(user)) {
			return await this.createTotpTransaction(user, data, 'password');
		}

		return await this.issueHandoff({
			userId: user.id.toString(),
			applicationId: data.application_id,
			returnTarget: data.return_target,
			pkceChallenge: data.pkce_challenge,
			authenticationMethods: ['password'],
		});
	}

	async requestPasswordRecovery(data: AltarAppsRecoveryRequest, request: Request): Promise<void> {
		if (data.environment !== this.config.environment) {
			throw new AltarAppsAuthRejectedError();
		}
		try {
			await AuthPassword.forgotPassword(this.ctx, {data: {email: data.email}, request});
		} catch (error) {
			const mapped = mapAuthError(error);
			if (mapped instanceof AltarAppsAuthRejectedError) {
				return;
			}
			throw mapped;
		}
	}

	async completePasswordRecovery(data: AltarAppsRecoveryCompleteRequest): Promise<AltarAppsAuthResponse> {
		this.assertBinding(data);
		let user: User;
		try {
			user = await AuthPassword.resetPasswordWithoutSession(this.ctx, {
				token: data.token,
				password: data.password,
			});
		} catch (error) {
			throw mapAuthError(error);
		}

		if (AuthLogin.requiresLoginMfa(user)) {
			return await this.createTotpTransaction(user, data, 'recovery_code');
		}

		return await this.issueHandoff({
			userId: user.id.toString(),
			applicationId: data.application_id,
			returnTarget: data.return_target,
			pkceChallenge: data.pkce_challenge,
			authenticationMethods: ['recovery_code'],
		});
	}

	async completeTotp(data: AltarAppsTotpRequest, request: Request): Promise<AltarAppsAuthResponse> {
		const cache = this.ctx.services.cache;
		const key = transactionKey(data.transaction);
		const payload = await cache.get<MfaTransaction>(key);
		if (!validMfaTransaction(payload)) {
			throw new AltarAppsAuthRejectedError();
		}
		const attemptsKey = transactionAttemptsKey(data.transaction);
		const attempts = (await cache.get<number>(attemptsKey)) ?? 0;
		if (attempts >= TRANSACTION_MAX_ATTEMPTS) {
			await cache.delete(key);
			await cache.delete(attemptsKey);
			throw new AltarAppsAuthRejectedError();
		}

		try {
			await AuthLogin.verifyMfaTotpForUser(this.ctx, this.loginDependencies, {
				userId: payload.userId,
				code: data.code,
				request,
				allowBackup: false,
				onInvalidCode: async () => {
					const nextAttempts = attempts + 1;
					if (nextAttempts >= TRANSACTION_MAX_ATTEMPTS) {
						await cache.delete(key);
						await cache.delete(attemptsKey);
					} else {
						await cache.set(attemptsKey, nextAttempts, TRANSACTION_TTL);
					}
				},
			});
		} catch (error) {
			throw mapAuthError(error);
		}

		const claimed = await cache.getAndDelete<MfaTransaction>(key);
		await cache.delete(attemptsKey);
		if (!sameMfaTransaction(payload, claimed)) {
			throw new AltarAppsAuthRejectedError();
		}
		return await this.issueHandoff({
			userId: claimed.userId,
			applicationId: claimed.applicationId,
			returnTarget: claimed.returnTarget,
			pkceChallenge: claimed.pkceChallenge,
			authenticationMethods: [claimed.primaryMethod, 'totp'],
		});
	}

	private assertBinding(data: AltarAppsBinding): void {
		if (
			data.environment !== this.config.environment ||
			!bindingAllowed(this.config, {
				applicationId: data.application_id,
				returnTarget: data.return_target,
			})
		) {
			throw new AltarAppsAuthRejectedError();
		}
	}

	private async createTotpTransaction(
		user: User,
		data: AltarAppsBinding,
		primaryMethod: 'password' | 'recovery_code',
	): Promise<AltarAppsAuthResponse> {
		const availability = await AuthLogin.getLoginMfaAvailability(this.ctx, user).catch(() => {
			throw new AltarAppsAuthUnavailableError();
		});
		if (!availability.hasTotp) {
			throw new AltarAppsAuthUnavailableError();
		}
		const transaction = `aat1_${await AuthUtility.generateSecureToken(this.ctx)}`;
		await this.ctx.services.cache.set<MfaTransaction>(
			transactionKey(transaction),
			{
				version: 2,
				userId: user.id.toString(),
				applicationId: data.application_id,
				returnTarget: data.return_target,
				pkceChallenge: data.pkce_challenge,
				primaryMethod,
			},
			TRANSACTION_TTL,
		);
		return {status: 'mfa_required', transaction, methods: ['totp']};
	}

	private async issueHandoff({
		userId,
		applicationId,
		returnTarget,
		pkceChallenge,
		authenticationMethods,
	}: {
		userId: string;
		applicationId: string;
		returnTarget: string;
		pkceChallenge: string;
		authenticationMethods: ReadonlyArray<'password' | 'totp' | 'recovery_code'>;
	}): Promise<AltarAppsAuthResponse> {
		try {
			const issued = await this.handoffs.issue({
				subject: userId,
				applicationId,
				returnTarget,
				pkceChallenge,
				authenticationMethods,
			});
			return {status: 'complete', handoff: issued.handoff, expires_at: issued.expiresAt};
		} catch {
			throw new AltarAppsAuthUnavailableError();
		}
	}
}

function transactionKey(transaction: string): string {
	return `altarapps-auth-transaction:${transactionDigest(transaction)}`;
}

function isChatAccessBody(value: unknown): value is {environment: 'test-demo'; subject: string} {
	if (value === null || typeof value !== 'object' || Array.isArray(value)) {
		return false;
	}
	const body = value as Record<string, unknown>;
	return (
		Object.keys(body).length === 2 &&
		body.environment === 'test-demo' &&
		typeof body.subject === 'string' &&
		/^[1-9][0-9]{0,19}$/.test(body.subject)
	);
}

function transactionAttemptsKey(transaction: string): string {
	return `altarapps-auth-transaction-attempts:${transactionDigest(transaction)}`;
}

function transactionDigest(transaction: string): string {
	return crypto.createHash('sha256').update(transaction).digest('base64url');
}

function validMfaTransaction(value: MfaTransaction | null): value is MfaTransaction {
	return (
		value !== null &&
		value.version === 2 &&
		/^[1-9][0-9]{0,19}$/.test(value.userId) &&
		/^[a-z][a-z0-9_-]{0,63}$/.test(value.applicationId) &&
		value.returnTarget.length > 0 &&
		value.returnTarget.length <= 2048 &&
		/^[A-Za-z0-9_-]{43}$/.test(value.pkceChallenge) &&
		(value.primaryMethod === 'password' || value.primaryMethod === 'recovery_code')
	);
}

function sameMfaTransaction(expected: MfaTransaction, actual: MfaTransaction | null): actual is MfaTransaction {
	return (
		validMfaTransaction(actual) &&
		actual.userId === expected.userId &&
		actual.applicationId === expected.applicationId &&
		actual.returnTarget === expected.returnTarget &&
		actual.pkceChallenge === expected.pkceChallenge &&
		actual.primaryMethod === expected.primaryMethod
	);
}

function mapAuthError(error: unknown): Error {
	if (
		error instanceof AltarAppsAuthRejectedError ||
		error instanceof AltarAppsAuthThrottledError ||
		error instanceof AltarAppsAuthUnavailableError
	) {
		return error;
	}
	if (error instanceof FluxerError) {
		if (error.status === 429) {
			const raw = error.headers?.['Retry-After'];
			const retryAfter = raw && /^\d+$/.test(raw) ? Number.parseInt(raw, 10) : 1;
			return new AltarAppsAuthThrottledError(Math.min(3600, Math.max(1, retryAfter)));
		}
		if (error.status < 500) {
			return new AltarAppsAuthRejectedError();
		}
	}
	return new AltarAppsAuthUnavailableError();
}
