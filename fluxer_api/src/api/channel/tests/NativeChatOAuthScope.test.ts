// SPDX-License-Identifier: AGPL-3.0-or-later

import {randomBytes} from 'node:crypto';
import {createApplicationID, createUserID} from '@app/api/BrandedTypes';
import {getOAuth2TokenRepository, getUserRepository} from '@app/api/middleware/ServiceSingletons';
import {ChannelTypes, Permissions} from '@fluxer/constants/src/ChannelConstants';
import {RelationshipTypes, UserFlags} from '@fluxer/constants/src/UserConstants';
import type {ChannelResponse} from '@fluxer/schema/src/domains/channel/ChannelSchemas';
import type {MessageResponse} from '@fluxer/schema/src/domains/message/MessageResponseSchemas';
import type {RelationshipResponse} from '@fluxer/schema/src/domains/user/UserResponseSchemas';
import {afterAll, beforeAll, beforeEach, describe, expect, it} from 'vitest';
import {createTestAccount} from '../../auth/tests/AuthTestUtils';
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

	it('Gateway initialization accepts chat only and rejects revoked tokens and closed accounts', async () => {
		const account = await createTestAccount(harness);
		const issue = (scope: Array<string>) =>
			getOAuth2TokenRepository().createAccessToken(
				{
					token_: randomBytes(32).toString('base64url'),
					application_id: createApplicationID(123456789n),
					user_id: createUserID(BigInt(account.userId)),
					scope: new Set(scope),
					created_at: new Date(),
				},
				900,
			);
		const identify = await issue(['identify']);
		const chat = await issue(['identify', 'chat']);
		const init = (token: string) =>
			createBuilder<{data: {user: {id: string}}}>(harness, '')
				.post('/test/rpc-session-init')
				.body({type: 'session', token, version: 1, ip: '127.0.0.1'});
		await init(identify.token).expect(401).execute();
		expect((await init(chat.token).expect(200).execute()).data.user.id).toBe(account.userId);
		await getOAuth2TokenRepository().deleteAllAccessTokensForUser(createUserID(BigInt(account.userId)));
		await init(chat.token).expect(401).execute();
		const another = await issue(['identify', 'chat']);
		await getUserRepository().updateFlags(createUserID(BigInt(account.userId)), (flags) => flags | UserFlags.DELETED);
		await init(another.token).expect(401).execute();
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

		await createBuilder<void>(harness, authorization)
			.put(`/channels/${systemChannel.id}/messages/${sent.id}/reactions/%F0%9F%91%8D/@me`)
			.expect(HTTP_STATUS.NO_CONTENT)
			.execute();
		const reacted = await createBuilder<MessageResponse>(harness, authorization)
			.get(`/channels/${systemChannel.id}/messages/${sent.id}`)
			.expect(HTTP_STATUS.OK)
			.execute();
		expect(reacted.reactions).toEqual([
			expect.objectContaining({count: 1, me: true, emoji: expect.objectContaining({name: '👍'})}),
		]);
		await createBuilder<void>(harness, authorization)
			.delete(`/channels/${systemChannel.id}/messages/${sent.id}/reactions/%F0%9F%91%8D/@me`)
			.expect(HTTP_STATUS.NO_CONTENT)
			.execute();

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

	it('allows native direct consent and opens the stock DM channel', async () => {
		const requester = await createTestAccount(harness);
		const recipient = await createTestAccount(harness);
		const requesterOAuth = await createOAuth2Token(harness, requester.userId, ['identify', 'chat']);
		const recipientOAuth = await createOAuth2Token(harness, recipient.userId, ['identify', 'chat']);

		const outgoing = await createBuilder<RelationshipResponse>(harness, `Bearer ${requesterOAuth.token}`)
			.post(`/users/@me/relationships/${recipient.userId}`)
			.body({})
			.expect(HTTP_STATUS.OK)
			.execute();
		expect(outgoing.id).toBe(recipient.userId);
		expect(outgoing.type).toBe(RelationshipTypes.OUTGOING_REQUEST);

		const accepted = await createBuilder<RelationshipResponse>(harness, `Bearer ${recipientOAuth.token}`)
			.put(`/users/@me/relationships/${requester.userId}`)
			.body({})
			.expect(HTTP_STATUS.OK)
			.execute();
		expect(accepted.id).toBe(requester.userId);
		expect(accepted.type).toBe(RelationshipTypes.FRIEND);

		const channel = await createBuilder<ChannelResponse>(harness, `Bearer ${recipientOAuth.token}`)
			.post('/users/@me/channels')
			.body({recipient_id: requester.userId})
			.expect(HTTP_STATUS.OK)
			.execute();
		expect(channel.type).toBe(ChannelTypes.DM);
		expect(channel.recipients?.map((user) => user.id)).toEqual([requester.userId]);

		await createBuilder<void>(harness, `Bearer ${requesterOAuth.token}`)
			.delete(`/users/@me/relationships/${recipient.userId}`)
			.expect(HTTP_STATUS.NO_CONTENT)
			.execute();
	});

	it('rejects a bearer without the chat scope', async () => {
		const {members, guild, systemChannel} = await setupTestGuildWithMembers(harness, 1);
		const member = members[0]!;
		const oauth = await createOAuth2Token(harness, member.userId, ['identify']);

		await createBuilder(harness, `Bearer ${oauth.token}`)
			.get(`/channels/${systemChannel.id}/messages`)
			.expect(HTTP_STATUS.FORBIDDEN, 'MISSING_OAUTH_SCOPE')
			.execute();

		for (const request of [
			createBuilder(harness, `Bearer ${oauth.token}`).patch(`/channels/${systemChannel.id}`).body({name: 'blocked'}),
			createBuilder(harness, `Bearer ${oauth.token}`)
				.put(`/channels/${systemChannel.id}/recipients/${members[0]!.userId}`)
				.body(null),
			createBuilder(harness, `Bearer ${oauth.token}`).delete(
				`/channels/${systemChannel.id}/recipients/${members[0]!.userId}`,
			),
			createBuilder(harness, `Bearer ${oauth.token}`).post(`/users/@me/relationships/${members[0]!.userId}`).body({}),
			createBuilder(harness, `Bearer ${oauth.token}`).put(`/users/@me/relationships/${members[0]!.userId}`).body({}),
			createBuilder(harness, `Bearer ${oauth.token}`).delete(`/users/@me/relationships/${members[0]!.userId}`),
			createBuilder(harness, `Bearer ${oauth.token}`)
				.post('/users/@me/channels')
				.body({recipient_id: members[0]!.userId}),
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
			createBuilder(harness, `Bearer ${oauth.token}`).put(
				`/channels/${systemChannel.id}/messages/123456789012345678/reactions/%F0%9F%91%8D/@me`,
			),
			createBuilder(harness, `Bearer ${oauth.token}`).delete(
				`/channels/${systemChannel.id}/messages/123456789012345678/reactions/%F0%9F%91%8D/@me`,
			),
			createBuilder(harness, `Bearer ${oauth.token}`).get('/gifs/trending'),
			createBuilder(harness, `Bearer ${oauth.token}`).get(`/guilds/${guild.id}/stickers`),
		]) {
			await request.expect(HTTP_STATUS.FORBIDDEN, 'MISSING_OAUTH_SCOPE').execute();
		}
	});
});
