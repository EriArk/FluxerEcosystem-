// SPDX-License-Identifier: AGPL-3.0-or-later

import type {ApiContext} from '../ApiContext';
import type * as AuthLogin from '../auth/AuthLogin';
import type * as AuthRegistration from '../auth/AuthRegistration';
import type {IKVProvider} from '@pkgs/kv_client/src/IKVProvider';
import type {IOAuth2TokenRepository} from '../oauth/repositories/IOAuth2TokenRepository';
import {loadAltarAppsAuthConfig} from './AltarAppsAuthConfig';
import {AltarAppsAuthService} from './AltarAppsAuthService';
import {AltarAppsTabletopClient} from './AltarAppsTabletopClient';

const config = loadAltarAppsAuthConfig(process.env);
const handoffs = config.enabled ? new AltarAppsTabletopClient(config) : null;

export function createAltarAppsAuthService(
	ctx: ApiContext,
	loginDependencies: AuthLogin.LoginDependencies,
	registrationDependencies: AuthRegistration.RegistrationDependencies,
	oauth2Tokens: IOAuth2TokenRepository,
	kvClient: IKVProvider,
): AltarAppsAuthService | null {
	if (!config.enabled || handoffs === null) {
		return null;
	}
	return new AltarAppsAuthService(ctx, loginDependencies, config, handoffs, {
		registrationDependencies,
		oauth2Tokens,
		kvClient,
	});
}
