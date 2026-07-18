// SPDX-License-Identifier: AGPL-3.0-or-later

import type {IEmailI18nService} from '@pkgs/email/src/EmailI18nService';
import type {EmailConfig} from '@pkgs/email/src/EmailProviderTypes';
import {EmailService} from '@pkgs/email/src/EmailService';
import {describe, expect, it, vi} from 'vitest';

const logger = vi.hoisted(() => ({
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
}));

vi.mock('@fluxer/logger/src/Logger', () => ({
	createLogger: () => logger,
}));

describe('EmailService disabled delivery', () => {
	it('does not render or log private email material', async () => {
		const getTemplate = vi.fn(() => {
			throw new Error('disabled email delivery must not render a template');
		});
		const emailI18n = {getTemplate} as unknown as IEmailI18nService;
		const config: EmailConfig = {
			enabled: false,
			fromEmail: 'disabled@example.invalid',
			fromName: 'Disabled',
			appBaseUrl: 'https://example.invalid',
			marketingBaseUrl: 'https://example.invalid',
		};
		const service = new EmailService(config, emailI18n);
		const privateValues = {
			email: 'private-user@example.invalid',
			username: 'private-username',
			token: 'private-recovery-token',
		};

		await expect(
			service.sendPasswordResetEmail(privateValues.email, privateValues.username, privateValues.token),
		).resolves.toBe(true);

		expect(getTemplate).not.toHaveBeenCalled();
		expect(logger.info).toHaveBeenCalledWith(
			{templateKey: 'password_reset'},
			'Email delivery skipped because the email service is disabled',
		);
		const logArguments = JSON.stringify(logger.info.mock.calls);
		for (const privateValue of Object.values(privateValues)) {
			expect(logArguments).not.toContain(privateValue);
		}
	});
});
