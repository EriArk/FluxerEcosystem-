// SPDX-License-Identifier: AGPL-3.0-or-later

import crypto from 'node:crypto';
import {FluxerError} from '@fluxer/errors/src/FluxerError';
import {seconds} from 'itty-time';
import type {ApiContext} from '../ApiContext';
import * as AuthLogin from '../auth/AuthLogin';
import * as AuthPassword from '../auth/AuthPassword';
import * as AuthUtility from '../auth/AuthUtility';
import type {User} from '../models/User';
import type {AltarAppsAuthConfig} from './AltarAppsAuthConfig';
import {bindingAllowed} from './AltarAppsAuthConfig';
import {
	AltarAppsAuthRejectedError,
	AltarAppsAuthThrottledError,
	AltarAppsAuthUnavailableError,
} from './AltarAppsAuthErrors';
import type {
	AltarAppsAuthResponse,
	AltarAppsPasswordLoginRequest,
	AltarAppsRecoveryCompleteRequest,
	AltarAppsRecoveryRequest,
	AltarAppsTotpRequest,
} from './AltarAppsAuthSchemas';
import type {AltarAppsHandoffIssuer} from './AltarAppsTabletopClient';

const TRANSACTION_TTL = seconds('5 minutes');
const TRANSACTION_MAX_ATTEMPTS = 5;

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
	) {}

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
