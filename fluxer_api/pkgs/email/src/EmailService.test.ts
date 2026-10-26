// SPDX-License-Identifier: AGPL-3.0-or-later

import type {EmailConfig, EmailMessage, IEmailProvider} from '@pkgs/email/src/EmailProviderTypes';
import {EmailService} from '@pkgs/email/src/EmailService';
import {describe, expect, it, vi} from 'vitest';

const {logInfo} = vi.hoisted(() => ({logInfo: vi.fn()}));
vi.mock('@fluxer/logger/src/Logger', () => ({
	createLogger: () => ({info: logInfo, error: vi.fn(), warn: vi.fn()}),
}));

const CONFIG: EmailConfig = {
	enabled: true,
	fromEmail: 'noreply@example.com',
	fromName: 'Fluxer',
	appBaseUrl: 'https://example.com',
	apiBaseUrl: 'https://api.example.com',
	appealsEmail: 'appeals@fluxer.com',
	privacyEmail: 'privacy@fluxer.com',
	safetyEmail: 'safety@fluxer.com',
	supportEmail: 'support@fluxer.com',
	productName: 'Fluxer',
	marketingBaseUrl: 'https://example.com',
	staticCdnBaseUrl: 'https://static.example.com',
	legalAddress: 'Fluxer Platform AB, c/o Embassy House, Östgötagatan 12, 116 25 Stockholm, Sweden',
	brandLogo: true,
};

function createCapturingServiceFor(config: EmailConfig): {service: EmailService; sent: Array<EmailMessage>} {
	const sent: Array<EmailMessage> = [];
	const provider: IEmailProvider = {
		sendEmail: async (message) => {
			sent.push(message);
			return true;
		},
	};
	return {service: new EmailService(config, provider), sent};
}

describe('EmailService', () => {
	it('never logs recipients or recovery secrets when delivery is disabled', async () => {
		logInfo.mockClear();
		const {service, sent} = createCapturingServiceFor({...CONFIG, enabled: false});
		await service.send('password_reset', 'private-person@example.com', {resetToken: 'private-reset-secret'}, 'en-US');
		expect(sent).toHaveLength(0);
		expect(logInfo).toHaveBeenCalledExactlyOnceWith('Email service disabled; message content suppressed');
		expect(JSON.stringify(logInfo.mock.calls)).not.toContain('private-');
	});
	it('keeps the HTML part on a plain-http instance whose links stay on its own origins', async () => {
		const {service, sent} = createCapturingServiceFor({
			...CONFIG,
			appBaseUrl: 'http://chat.example.org',
			apiBaseUrl: 'http://chat.example.org/api',
			marketingBaseUrl: 'http://chat.example.org',
			staticCdnBaseUrl: 'http://static.chat.example.org:8080',
		});
		await service.send('password_reset', 'user@example.com', {resetToken: 'tok.abc'}, 'en-US');
		const html = sent[0].html ?? '';
		expect(html).toContain('href="http://chat.example.org/reset#token=tok.abc"');
		expect(html).toContain('src="http://static.chat.example.org:8080/email/brand/v1/logo-color.png"');
		expect(html).not.toContain('%%');
	});
});
