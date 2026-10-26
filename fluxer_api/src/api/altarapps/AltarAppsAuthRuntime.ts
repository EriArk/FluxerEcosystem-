// SPDX-License-Identifier: AGPL-3.0-or-later

import type {ApiContext} from '@app/api/ApiContext';
import {loadAltarAppsAuthConfig} from '@app/api/altarapps/AltarAppsAuthConfig';
import {AltarAppsAuthService} from '@app/api/altarapps/AltarAppsAuthService';
import {AltarAppsTabletopClient} from '@app/api/altarapps/AltarAppsTabletopClient';
import type * as AuthLogin from '@app/api/auth/AuthLogin';
import type * as AuthRegistration from '@app/api/auth/AuthRegistration';
import type {OAuth2TokenRepository} from '@app/api/oauth/repositories/OAuth2TokenRepository';
import type {IKVProvider} from '@pkgs/kv_client/src/IKVProvider';

const config = loadAltarAppsAuthConfig(process.env);
const handoffs = config.enabled ? new AltarAppsTabletopClient(config) : null;

export function createAltarAppsAuthService(
	ctx: ApiContext,
	loginDependencies: AuthLogin.LoginDependencies,
	registrationDependencies: AuthRegistration.RegistrationDependencies,
	oauth2Tokens: OAuth2TokenRepository,
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
