// SPDX-License-Identifier: AGPL-3.0-or-later

import {Permissions} from '@fluxer/constants/src/ChannelConstants';
import type {MessageResponse} from '@fluxer/schema/src/domains/message/MessageResponseSchemas';
import {afterAll, beforeAll, beforeEach, describe, expect, it} from 'vitest';
import {addMemberRole, createRole} from '../../guild/tests/GuildTestUtils';
import {ensureSessionStarted} from '../../message/tests/MessageTestUtils';
import {type ApiTestHarness, createApiTestHarness} from '../../test/ApiTestHarness';
import {HTTP_STATUS} from '../../test/TestConstants';
import {createBuilder} from '../../test/TestRequestBuilder';
import {leaveGuild, setupTestGuildWithMembers} from './ChannelTestUtils';

interface OAuth2TokenResponse {
	token: string;
}

async function createOAuth2Token(
	harness: ApiTestHarness,
	userId: string,
	scopes: Array<string>,
): Promise<OAuth2TokenResponse> {
	return createBuilder<OAuth2TokenResponse>(harness, '')
		.post('/test/oauth2/access-token')
		.body({user_id: userId, scopes})
		.execute();
}

describe('native chat OAuth scope', () => {
	let harness: ApiTestHarness;

	beforeAll(async () => {
		harness = await createApiTestHarness();
	});

	beforeEach(async () => {
		await harness.reset();
	});

	afterAll(async () => {
		await harness?.shutdown();
	});

	it('allows native history, send, edit, delete, and acknowledgement, then honors membership removal', async () => {
		const {owner, members, guild, systemChannel} = await setupTestGuildWithMembers(harness, 1);
		const member = members[0]!;
		const pinRole = await createRole(harness, owner.token, guild.id, {
			name: 'Native pin proof',
			permissions: Permissions.PIN_MESSAGES.toString(),
		});
		await addMemberRole(harness, owner.token, guild.id, member.userId, pinRole.id);
		await ensureSessionStarted(harness, member.token);
		const oauth = await createOAuth2Token(harness, member.userId, ['identify', 'chat']);
		const authorization = `Bearer ${oauth.token}`;

		const sent = await createBuilder<MessageResponse>(harness, authorization)
			.post(`/channels/${systemChannel.id}/messages`)
			.body({content: 'native chat proof'})
			.expect(HTTP_STATUS.OK)
			.execute();
		expect(sent.author.id).toBe(member.userId);

		const history = await createBuilder<Array<MessageResponse>>(harness, authorization)
			.get(`/channels/${systemChannel.id}/messages`)
			.expect(HTTP_STATUS.OK)
			.execute();
		expect(history.some((message) => message.id === sent.id)).toBe(true);

		const edited = await createBuilder<MessageResponse>(harness, authorization)
			.patch(`/channels/${systemChannel.id}/messages/${sent.id}`)
			.body({content: 'native chat proof edited'})
			.expect(HTTP_STATUS.OK)
			.execute();
		expect(edited.author.id).toBe(member.userId);
		expect(edited.content).toBe('native chat proof edited');

		await createBuilder<void>(harness, authorization)
			.put(`/channels/${systemChannel.id}/pins/${sent.id}`)
			.expect(HTTP_STATUS.NO_CONTENT)
			.execute();
		await createBuilder<void>(harness, authorization)
			.delete(`/channels/${systemChannel.id}/pins/${sent.id}`)
			.expect(HTTP_STATUS.NO_CONTENT)
			.execute();

		await createBuilder<void>(harness, authorization)
			.post(`/channels/${systemChannel.id}/messages/${sent.id}/ack`)
			.body({manual: true, mention_count: 0})
			.expect(HTTP_STATUS.NO_CONTENT)
			.execute();

		await createBuilder<void>(harness, authorization)
			.delete(`/channels/${systemChannel.id}/messages/${sent.id}`)
			.expect(HTTP_STATUS.NO_CONTENT)
			.execute();

		await leaveGuild(harness, member.token, guild.id);
		const afterRemoval = await createBuilder(harness, authorization)
			.get(`/channels/${systemChannel.id}/messages`)
			.executeRaw();
		expect(afterRemoval.response.status).toBe(HTTP_STATUS.FORBIDDEN);
	});

	it('rejects a bearer without the chat scope', async () => {
		const {members, systemChannel} = await setupTestGuildWithMembers(harness, 1);
		const member = members[0]!;
		const oauth = await createOAuth2Token(harness, member.userId, ['identify']);

		await createBuilder(harness, `Bearer ${oauth.token}`)
			.get(`/channels/${systemChannel.id}/messages`)
			.expect(HTTP_STATUS.FORBIDDEN, 'MISSING_OAUTH_SCOPE')
			.execute();

		for (const request of [
			createBuilder(harness, `Bearer ${oauth.token}`)
				.post(`/channels/${systemChannel.id}/attachments`)
				.body({attachments: []}),
			createBuilder(harness, `Bearer ${oauth.token}`)
				.post(`/channels/${systemChannel.id}/attachments/complete`)
				.body({uploads: []}),
			createBuilder(harness, `Bearer ${oauth.token}`)
				.patch(`/channels/${systemChannel.id}/messages/123456789012345678`)
				.body({content: 'blocked'}),
			createBuilder(harness, `Bearer ${oauth.token}`).delete(
				`/channels/${systemChannel.id}/messages/123456789012345678`,
			),
			createBuilder(harness, `Bearer ${oauth.token}`).put(`/channels/${systemChannel.id}/pins/123456789012345678`),
			createBuilder(harness, `Bearer ${oauth.token}`).delete(`/channels/${systemChannel.id}/pins/123456789012345678`),
		]) {
			await request.expect(HTTP_STATUS.FORBIDDEN, 'MISSING_OAUTH_SCOPE').execute();
		}
	});
});
