// SPDX-License-Identifier: AGPL-3.0-or-later

import crypto from 'node:crypto';
import {ChannelTypes, Permissions} from '@fluxer/constants/src/ChannelConstants';
import {JoinSourceTypes} from '@fluxer/constants/src/GuildConstants';
import {UnknownGuildMemberError} from '@fluxer/errors/src/domains/guild/UnknownGuildMemberError';
import {describe, expect, test, vi} from 'vitest';
import type {ApiContext} from '../../ApiContext';
import type {LoginDependencies} from '../../auth/AuthLogin';
import type {GuildService} from '../../guild/services/GuildService';
import type {RequestCache} from '../../middleware/RequestCacheMiddleware';
import type {User} from '../../models/User';
import {MockKVProvider} from '../../test/mocks/MockKVProvider';
import type {AltarAppsAuthConfig} from '../AltarAppsAuthConfig';
import {ALTARAPPS_CHAT_TOPOLOGY_PATH} from '../AltarAppsAuthConfig';
import {AltarAppsAuthRejectedError} from '../AltarAppsAuthErrors';
import {AltarAppsAuthService} from '../AltarAppsAuthService';
import type {AltarAppsHandoffIssuer} from '../AltarAppsTabletopClient';

const SERVICE_KEY = Buffer.alloc(32, 7);
const SPACE_KEY = '019c2b9e-8d4b-7a35-8a62-6cc6c0e3b741';
const TOPIC_KEY = '019c2b9e-8d4b-7a35-8a62-6cc6c0e3b742';
const CATEGORY_KEY = '019c2b9e-8d4b-7a35-8a62-6cc6c0e3b743';
const GUILD_ID = '1530254793384132609';
const CHANNEL_ID = '1530254793384132610';
const TOPIC_CHANNEL_ID = '1530254793384132611';
const CATEGORY_CHANNEL_ID = '1530254793384132615';
const USER_ID = '1530254793384132612';
const OWNER_ID = '1530254793384132613';
const PIN_ROLE_ID = '1530254793384132614';

function config(): Extract<AltarAppsAuthConfig, {enabled: true}> {
	return {
		enabled: true,
		environment: 'test-demo',
		tabletopUrl: 'http://tabletop:8080/internal/v1/auth/verified-identity-handoffs',
		serviceId: 'fluxer',
		audience: 'tabletop-api',
		keyId: 'fluxer-test-1',
		serviceKey: SERVICE_KEY,
		allowedBindings: new Map(),
		chatOwnerUserId: OWNER_ID,
		timeoutMs: 2000,
	};
}

function signedRequest(body: Record<string, unknown>, nonceByte: number) {
	const encoded = Buffer.from(JSON.stringify(body));
	const timestamp = Math.floor(Date.now() / 1000).toString();
	const nonce = Buffer.alloc(24, nonceByte).toString('base64url');
	const digest = crypto.createHash('sha256').update(encoded).digest('base64url');
	const canonical = [
		'altarapps-chat-topology-v1',
		'tabletop',
		'fluxer-api',
		'POST',
		ALTARAPPS_CHAT_TOPOLOGY_PATH,
		'fluxer-test-1',
		timestamp,
		nonce,
		digest,
	].join('\n');
	const signature = crypto.createHmac('sha256', SERVICE_KEY).update(canonical).digest('base64url');
	return {
		method: 'POST',
		headers: new Headers({
			'content-type': 'application/json',
			'content-length': encoded.length.toString(),
			'x-altar-key-id': 'fluxer-test-1',
			'x-altar-timestamp': timestamp,
			'x-altar-nonce': nonce,
			'x-altar-signature': signature,
		}),
		body: encoded,
	};
}

function setup() {
	const kv = new MockKVProvider();
	const users = new Map<string, User>([
		[OWNER_ID, {id: BigInt(OWNER_ID), isBot: false, emailVerified: true, pendingDeletionAt: null} as User],
		[USER_ID, {id: BigInt(USER_ID), isBot: false, pendingDeletionAt: null} as User],
	]);
	const startGuild = vi.fn(async () => {});
	const ctx = {
		services: {
			users: {findUnique: vi.fn(async (id: bigint) => users.get(id.toString()) ?? null)},
			gateway: {startGuild},
		},
	} as unknown as ApiContext;
	const service = new AltarAppsAuthService(
		ctx,
		{} as LoginDependencies,
		config(),
		{issue: vi.fn()} as unknown as AltarAppsHandoffIssuer,
		{
			registrationDependencies: {} as never,
			oauth2Tokens: {} as never,
			kvClient: kv,
		},
	);
	const spaces: Array<Record<string, unknown>> = [];
	const createGuild = vi.fn(async () => {
		const created = {
			id: GUILD_ID,
			name: `aa-space-${SPACE_KEY}`,
			owner_id: OWNER_ID,
			system_channel_id: CHANNEL_ID,
		};
		spaces.push(created);
		return created;
	});
	const addUserToGuild = vi.fn(async () => ({}));
	const leaveGuild = vi.fn(async () => {});
	const addMemberRole = vi.fn(async () => {});
	const removeMemberRole = vi.fn(async () => {});
	const roles: Array<Record<string, unknown>> = [];
	const systemCreateRole = vi.fn(async () => {
		const role = {
			id: PIN_ROLE_ID,
			name: 'aa-cap-pin-messages',
			permissions: Permissions.PIN_MESSAGES.toString(),
		};
		roles.push(role);
		return role;
	});
	const channels: Array<Record<string, unknown>> = [];
	const createChannel = vi.fn(async ({data}: {data: Record<string, unknown>}) => {
		const category = data.type === ChannelTypes.GUILD_CATEGORY;
		const created = {
			id: category ? CATEGORY_CHANNEL_ID : TOPIC_CHANNEL_ID,
			guild_id: GUILD_ID,
			name: data.name,
			type: data.type,
			parent_id: data.parent_id,
		};
		channels.push(created);
		return created;
	});
	const guildService = {
		data: {
			getUserGuilds: vi.fn(async () => spaces),
			createGuild,
			getGuildSystem: vi.fn(async () => ({
				id: BigInt(GUILD_ID),
				ownerId: BigInt(OWNER_ID),
				name: `aa-space-${SPACE_KEY}`,
			})),
		},
		channels: {
			getChannels: vi.fn(async () => channels),
			createChannel,
		},
		members: {addUserToGuild, leaveGuild, addMemberRole, removeMemberRole},
		roles: {
			listRoles: vi.fn(async () => roles),
			systemCreateRole,
		},
	} as unknown as GuildService;
	return {
		service,
		guildService,
		requestCache: {} as RequestCache,
		createGuild,
		createChannel,
		addUserToGuild,
		leaveGuild,
		addMemberRole,
		removeMemberRole,
		systemCreateRole,
		roles,
		startGuild,
	};
}

describe('AltarApps native chat topology', () => {
	test('idempotently creates one service-owned native space', async () => {
		const {service, guildService, requestCache, createGuild, startGuild} = setup();
		const body = {environment: 'test-demo', operation: 'ensure_space', space_key: SPACE_KEY};

		await expect(service.applyChatTopology(signedRequest(body, 1), guildService, requestCache)).resolves.toEqual({
			operation: 'ensure_space',
			guild_id: GUILD_ID,
			channel_id: CHANNEL_ID,
		});
		await expect(service.applyChatTopology(signedRequest(body, 2), guildService, requestCache)).resolves.toEqual({
			operation: 'ensure_space',
			guild_id: GUILD_ID,
			channel_id: CHANNEL_ID,
		});
		expect(createGuild).toHaveBeenCalledOnce();
		expect(createGuild).toHaveBeenCalledWith({
			user: expect.objectContaining({id: BigInt(OWNER_ID)}),
			data: {name: `aa-space-${SPACE_KEY}`, icon: null, empty_features: true},
		});
		expect(startGuild).toHaveBeenCalledTimes(2);
		expect(startGuild).toHaveBeenCalledWith(BigInt(GUILD_ID));
	});

	test('creates a deterministic native topic without permission overwrites', async () => {
		const {service, guildService, requestCache, createChannel, startGuild} = setup();
		const body = {
			environment: 'test-demo',
			operation: 'ensure_topic',
			space_key: SPACE_KEY,
			topic_key: TOPIC_KEY,
			guild_id: GUILD_ID,
		};

		await expect(service.applyChatTopology(signedRequest(body, 3), guildService, requestCache)).resolves.toEqual({
			operation: 'ensure_topic',
			guild_id: GUILD_ID,
			channel_id: TOPIC_CHANNEL_ID,
		});
		expect(createChannel).toHaveBeenCalledWith({
			userId: BigInt(OWNER_ID),
			guildId: BigInt(GUILD_ID),
			data: {type: ChannelTypes.GUILD_TEXT, name: `aa-topic-${TOPIC_KEY}`, nsfw: false},
			requestCache,
		});
		expect(startGuild).toHaveBeenCalledOnce();
		expect(startGuild).toHaveBeenCalledWith(BigInt(GUILD_ID));
	});

	test('creates one native category and places its topic below it', async () => {
		const {service, guildService, requestCache, createChannel} = setup();
		const categoryBody = {
			environment: 'test-demo',
			operation: 'ensure_category',
			space_key: SPACE_KEY,
			category_key: CATEGORY_KEY,
			guild_id: GUILD_ID,
		};

		await expect(
			service.applyChatTopology(signedRequest(categoryBody, 8), guildService, requestCache),
		).resolves.toEqual({
			operation: 'ensure_category',
			guild_id: GUILD_ID,
			channel_id: CATEGORY_CHANNEL_ID,
		});
		await expect(
			service.applyChatTopology(
				signedRequest(
					{
						environment: 'test-demo',
						operation: 'ensure_topic',
						space_key: SPACE_KEY,
						topic_key: TOPIC_KEY,
						guild_id: GUILD_ID,
						category_id: CATEGORY_CHANNEL_ID,
					},
					9,
				),
				guildService,
				requestCache,
			),
		).resolves.toEqual({
			operation: 'ensure_topic',
			guild_id: GUILD_ID,
			channel_id: TOPIC_CHANNEL_ID,
		});
		expect(createChannel).toHaveBeenNthCalledWith(1, {
			userId: BigInt(OWNER_ID),
			guildId: BigInt(GUILD_ID),
			data: {type: ChannelTypes.GUILD_CATEGORY, name: `aa-category-${CATEGORY_KEY}`, nsfw: false},
			requestCache,
		});
		expect(createChannel).toHaveBeenNthCalledWith(2, {
			userId: BigInt(OWNER_ID),
			guildId: BigInt(GUILD_ID),
			data: {
				type: ChannelTypes.GUILD_TEXT,
				name: `aa-topic-${TOPIC_KEY}`,
				nsfw: false,
				parent_id: BigInt(CATEGORY_CHANNEL_ID),
			},
			requestCache,
		});
	});

	test('projects only the native pin role while keeping membership operations idempotent', async () => {
		const {
			service,
			guildService,
			requestCache,
			addUserToGuild,
			leaveGuild,
			addMemberRole,
			removeMemberRole,
			systemCreateRole,
		} = setup();
		const base = {environment: 'test-demo', space_key: SPACE_KEY, guild_id: GUILD_ID, subject: USER_ID};

		await expect(
			service.applyChatTopology(
				signedRequest({...base, operation: 'ensure_membership', can_pin_messages: true}, 4),
				guildService,
				requestCache,
			),
		).resolves.toMatchObject({membership_state: 'active'});
		expect(addUserToGuild).toHaveBeenCalledWith({
			userId: BigInt(USER_ID),
			guildId: BigInt(GUILD_ID),
			sendJoinMessage: false,
			skipGuildLimitCheck: true,
			skipBanCheck: false,
			joinSourceType: JoinSourceTypes.ADMIN_FORCE_ADD,
			requestCache,
			initiatorId: BigInt(OWNER_ID),
		});
		expect(systemCreateRole).toHaveBeenCalledWith({
			initiatorId: BigInt(OWNER_ID),
			guildId: BigInt(GUILD_ID),
			data: {name: 'aa-cap-pin-messages', color: 0, permissions: Permissions.PIN_MESSAGES},
		});
		expect(addMemberRole).toHaveBeenCalledWith({
			userId: BigInt(OWNER_ID),
			targetId: BigInt(USER_ID),
			guildId: BigInt(GUILD_ID),
			roleId: BigInt(PIN_ROLE_ID),
			requestCache,
		});

		await expect(
			service.applyChatTopology(
				signedRequest({...base, operation: 'ensure_membership', can_pin_messages: false}, 5),
				guildService,
				requestCache,
			),
		).resolves.toMatchObject({membership_state: 'active'});
		expect(systemCreateRole).toHaveBeenCalledOnce();
		expect(removeMemberRole).toHaveBeenCalledWith({
			userId: BigInt(OWNER_ID),
			targetId: BigInt(USER_ID),
			guildId: BigInt(GUILD_ID),
			roleId: BigInt(PIN_ROLE_ID),
			requestCache,
		});

		leaveGuild.mockRejectedValueOnce(new UnknownGuildMemberError());
		await expect(
			service.applyChatTopology(
				signedRequest({...base, operation: 'remove_membership'}, 6),
				guildService,
				requestCache,
			),
		).resolves.toMatchObject({membership_state: 'absent'});
	});

	test('refuses a managed pin role whose permission set was changed', async () => {
		const {service, guildService, requestCache, roles, addMemberRole} = setup();
		roles.push({
			id: PIN_ROLE_ID,
			name: 'aa-cap-pin-messages',
			permissions: (Permissions.PIN_MESSAGES | Permissions.MANAGE_MESSAGES).toString(),
		});
		const body = {
			environment: 'test-demo',
			operation: 'ensure_membership',
			space_key: SPACE_KEY,
			guild_id: GUILD_ID,
			subject: USER_ID,
			can_pin_messages: true,
		};

		await expect(service.applyChatTopology(signedRequest(body, 7), guildService, requestCache)).rejects.toThrow();
		expect(addMemberRole).not.toHaveBeenCalled();
	});

	test('rejects assertion replay before executing a second topology operation', async () => {
		const {service, guildService, requestCache, createGuild} = setup();
		const request = signedRequest({environment: 'test-demo', operation: 'ensure_space', space_key: SPACE_KEY}, 8);
		await service.applyChatTopology(request, guildService, requestCache);

		await expect(service.applyChatTopology(request, guildService, requestCache)).rejects.toBeInstanceOf(
			AltarAppsAuthRejectedError,
		);
		expect(createGuild).toHaveBeenCalledOnce();
	});
});
