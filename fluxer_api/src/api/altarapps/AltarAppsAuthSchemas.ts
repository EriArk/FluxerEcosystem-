// SPDX-License-Identifier: AGPL-3.0-or-later

import {EmailType, GlobalNameType, PasswordType} from '@fluxer/schema/src/primitives/UserValidators';
import {z} from 'zod';

const Environment = z.literal('test-demo');
const ApplicationId = z
	.string()
	.min(1)
	.max(64)
	.regex(/^[a-z][a-z0-9_-]*$/);
const ReturnTarget = z.url().max(2048);
const PKCEChallenge = z
	.string()
	.length(43)
	.regex(/^[A-Za-z0-9_-]+$/)
	.refine((value) => {
		const decoded = Buffer.from(value, 'base64url');
		return decoded.length === 32 && decoded.toString('base64url') === value;
	});
const Transaction = z.string().regex(/^aat1_[A-Za-z0-9]{64}$/);
const RecoveryToken = z
	.string()
	.length(64)
	.regex(/^[A-Za-z0-9]+$/);

const AltarAppsBinding = z.object({
	environment: Environment,
	application_id: ApplicationId,
	return_target: ReturnTarget,
	pkce_challenge: PKCEChallenge,
});

export const AltarAppsPasswordLoginRequest = AltarAppsBinding.extend({
	email: EmailType,
	password: PasswordType,
}).strict();

export type AltarAppsPasswordLoginRequest = z.infer<typeof AltarAppsPasswordLoginRequest>;

export const AltarAppsRegistrationRequest = AltarAppsBinding.extend({
	email: EmailType,
	display_name: GlobalNameType,
	password: PasswordType,
}).strict();

export type AltarAppsRegistrationRequest = z.infer<typeof AltarAppsRegistrationRequest>;

export const AltarAppsRegistrationResponse = z
	.object({
		status: z.literal('verification_required'),
		email: EmailType,
	})
	.strict();

export type AltarAppsRegistrationResponse = z.infer<typeof AltarAppsRegistrationResponse>;

export const AltarAppsRegistrationResendRequest = z
	.object({
		environment: Environment,
		email: EmailType,
	})
	.strict();

export type AltarAppsRegistrationResendRequest = z.infer<typeof AltarAppsRegistrationResendRequest>;

export const AltarAppsTotpRequest = z
	.object({
		transaction: Transaction,
		code: z.string().regex(/^\d{6}$/),
	})
	.strict();

export type AltarAppsTotpRequest = z.infer<typeof AltarAppsTotpRequest>;

export const AltarAppsRecoveryRequest = z
	.object({
		environment: Environment,
		email: EmailType,
	})
	.strict();

export type AltarAppsRecoveryRequest = z.infer<typeof AltarAppsRecoveryRequest>;

export const AltarAppsRecoveryCompleteRequest = AltarAppsBinding.extend({
	token: RecoveryToken,
	password: PasswordType,
}).strict();

export type AltarAppsRecoveryCompleteRequest = z.infer<typeof AltarAppsRecoveryCompleteRequest>;

export const AltarAppsAuthHandoffResponse = z
	.object({
		status: z.literal('complete'),
		handoff: z.string().regex(/^aah1_[A-Za-z0-9_-]{43}$/),
		expires_at: z.iso.datetime({offset: false}),
	})
	.strict();

export const AltarAppsAuthMfaResponse = z
	.object({
		status: z.literal('mfa_required'),
		transaction: Transaction,
		methods: z
			.array(z.enum(['totp', 'passkey']))
			.min(1)
			.max(2),
	})
	.strict();

export const AltarAppsAuthResponse = z.union([AltarAppsAuthHandoffResponse, AltarAppsAuthMfaResponse]);
export type AltarAppsAuthResponse = z.infer<typeof AltarAppsAuthResponse>;

export const AltarAppsAuthErrorResponse = z
	.object({
		code: z.enum(['invalid_credentials', 'retry_later', 'sign_in_unavailable']),
		retry_after: z.number().int().min(1).max(3600).optional(),
	})
	.strict();
