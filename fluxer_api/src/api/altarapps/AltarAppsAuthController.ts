// SPDX-License-Identifier: AGPL-3.0-or-later

import type {Context} from 'hono';
import {Logger} from '../Logger';
import {LocalAuthMiddleware} from '../middleware/LocalAuthMiddleware';
import {OpenAPI} from '../middleware/ResponseTypeMiddleware';
import type {HonoApp, HonoEnv} from '../types/HonoEnv';
import {Validator} from '../Validator';
import {ALTARAPPS_CHAT_ACCESS_PATH} from './AltarAppsAuthConfig';
import {
	AltarAppsAuthRejectedError,
	AltarAppsAuthThrottledError,
	AltarAppsAuthUnavailableError,
} from './AltarAppsAuthErrors';
import {
	AltarAppsAuthResponse,
	AltarAppsPasswordLoginRequest,
	AltarAppsRegistrationRequest,
	AltarAppsRegistrationResendRequest,
	AltarAppsRegistrationResponse,
	AltarAppsRecoveryCompleteRequest,
	AltarAppsRecoveryRequest,
	AltarAppsTotpRequest,
} from './AltarAppsAuthSchemas';

export function AltarAppsAuthController(app: HonoApp) {
	app.post(ALTARAPPS_CHAT_ACCESS_PATH, async (ctx) => {
		secureResponse(ctx);
		const service = ctx.get('altarAppsAuthService');
		if (service === null) {
			return ctx.json({code: 'not_found'}, 404);
		}
		try {
			return ctx.json(await service.issueChatAccess(ctx.req.raw));
		} catch (error) {
			return authError(ctx, error);
		}
	});

	app.post(
		'/altarapps/v1/auth/register',
		async (ctx, next) => {
			secureResponse(ctx);
			if (ctx.get('altarAppsAuthService') === null) {
				return ctx.json({code: 'not_found'}, 404);
			}
			return await next();
		},
		LocalAuthMiddleware,
		Validator('json', AltarAppsRegistrationRequest),
		OpenAPI({
			operationId: 'altarapps_register',
			summary: 'Create an AltarApps account',
			responseSchema: AltarAppsRegistrationResponse,
			statusCode: 200,
			security: [],
			tags: ['AltarApps Auth'],
			description: 'Create a first-party player identity without exposing a Fluxer session.',
		}),
		async (ctx) => {
			secureResponse(ctx);
			try {
				const result = await ctx
					.get('altarAppsAuthService')!
					.register(ctx.req.valid('json'), ctx.req.raw, ctx.get('requestCache'));
				return ctx.json(result);
			} catch (error) {
				return authError(ctx, error);
			}
		},
	);

	app.post(
		'/altarapps/v1/auth/register/resend',
		async (ctx, next) => {
			secureResponse(ctx);
			if (ctx.get('altarAppsAuthService') === null) {
				return ctx.json({code: 'not_found'}, 404);
			}
			return await next();
		},
		LocalAuthMiddleware,
		Validator('json', AltarAppsRegistrationResendRequest),
		OpenAPI({
			operationId: 'altarapps_resend_registration_email',
			summary: 'Resend AltarApps account verification',
			responseSchema: null,
			statusCode: 204,
			security: [],
			tags: ['AltarApps Auth'],
			description: 'Send a generic bounded verification retry without disclosing account existence.',
		}),
		async (ctx) => {
			secureResponse(ctx);
			try {
				await ctx.get('altarAppsAuthService')!.resendRegistrationEmail(ctx.req.valid('json'));
				return ctx.body(null, 204);
			} catch (error) {
				return authError(ctx, error);
			}
		},
	);

	app.post(
		'/altarapps/v1/auth/password',
		async (ctx, next) => {
			secureResponse(ctx);
			if (ctx.get('altarAppsAuthService') === null) {
				return ctx.json({code: 'not_found'}, 404);
			}
			return await next();
		},
		LocalAuthMiddleware,
		Validator('json', AltarAppsPasswordLoginRequest),
		OpenAPI({
			operationId: 'altarapps_password_login',
			summary: 'Start AltarApps sign-in',
			responseSchema: AltarAppsAuthResponse,
			statusCode: 200,
			security: [],
			tags: ['AltarApps Auth'],
			description: 'Verify a first-party password without creating or returning a Fluxer session.',
		}),
		async (ctx) => {
			secureResponse(ctx);
			try {
				const result = await ctx.get('altarAppsAuthService')!.passwordLogin(ctx.req.valid('json'), ctx.req.raw);
				return ctx.json(result);
			} catch (error) {
				return authError(ctx, error);
			}
		},
	);

	app.post(
		'/altarapps/v1/auth/recovery/request',
		async (ctx, next) => {
			secureResponse(ctx);
			if (ctx.get('altarAppsAuthService') === null) {
				return ctx.json({code: 'not_found'}, 404);
			}
			return await next();
		},
		LocalAuthMiddleware,
		Validator('json', AltarAppsRecoveryRequest),
		OpenAPI({
			operationId: 'altarapps_request_password_recovery',
			summary: 'Request AltarApps password recovery',
			responseSchema: null,
			statusCode: 204,
			security: [],
			tags: ['AltarApps Auth'],
			description: 'Request a generic first-party recovery email without disclosing account existence.',
		}),
		async (ctx) => {
			secureResponse(ctx);
			try {
				await ctx.get('altarAppsAuthService')!.requestPasswordRecovery(ctx.req.valid('json'), ctx.req.raw);
				return ctx.body(null, 204);
			} catch (error) {
				return authError(ctx, error);
			}
		},
	);

	app.post(
		'/altarapps/v1/auth/recovery/complete',
		async (ctx, next) => {
			secureResponse(ctx);
			if (ctx.get('altarAppsAuthService') === null) {
				return ctx.json({code: 'not_found'}, 404);
			}
			return await next();
		},
		LocalAuthMiddleware,
		Validator('json', AltarAppsRecoveryCompleteRequest),
		OpenAPI({
			operationId: 'altarapps_complete_password_recovery',
			summary: 'Complete AltarApps password recovery',
			responseSchema: AltarAppsAuthResponse,
			statusCode: 200,
			security: [],
			tags: ['AltarApps Auth'],
			description:
				'Consume a recovery proof, revoke old sessions and return only an MFA transaction or one-use handoff.',
		}),
		async (ctx) => {
			secureResponse(ctx);
			try {
				const result = await ctx.get('altarAppsAuthService')!.completePasswordRecovery(ctx.req.valid('json'));
				return ctx.json(result);
			} catch (error) {
				return authError(ctx, error);
			}
		},
	);

	app.post(
		'/altarapps/v1/auth/mfa/totp',
		async (ctx, next) => {
			secureResponse(ctx);
			if (ctx.get('altarAppsAuthService') === null) {
				return ctx.json({code: 'not_found'}, 404);
			}
			return await next();
		},
		LocalAuthMiddleware,
		Validator('json', AltarAppsTotpRequest),
		OpenAPI({
			operationId: 'altarapps_complete_totp',
			summary: 'Complete AltarApps TOTP sign-in',
			responseSchema: AltarAppsAuthResponse,
			statusCode: 200,
			security: [],
			tags: ['AltarApps Auth'],
			description: 'Consume an AltarApps-only MFA transaction and return only a one-use handoff.',
		}),
		async (ctx) => {
			secureResponse(ctx);
			try {
				const result = await ctx.get('altarAppsAuthService')!.completeTotp(ctx.req.valid('json'), ctx.req.raw);
				return ctx.json(result);
			} catch (error) {
				return authError(ctx, error);
			}
		},
	);
}

function authError(ctx: Context<HonoEnv>, error: unknown) {
	secureResponse(ctx);
	if (error instanceof AltarAppsAuthThrottledError) {
		ctx.header('Retry-After', error.retryAfter.toString());
		return ctx.json({code: 'retry_later', retry_after: error.retryAfter}, 429);
	}
	if (error instanceof AltarAppsAuthRejectedError) {
		return ctx.json({code: 'invalid_credentials'}, 401);
	}
	if (!(error instanceof AltarAppsAuthUnavailableError)) {
		Logger.warn('Unexpected AltarApps sign-in failure was redacted');
	} else {
		Logger.warn('AltarApps sign-in dependency unavailable');
	}
	ctx.header('Retry-After', '1');
	return ctx.json({code: 'sign_in_unavailable'}, 503);
}

function secureResponse(ctx: Context<HonoEnv>): void {
	ctx.header('Cache-Control', 'no-store');
	ctx.header('Referrer-Policy', 'no-referrer');
	ctx.header('X-Content-Type-Options', 'nosniff');
}
