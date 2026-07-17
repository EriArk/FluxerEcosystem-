// SPDX-License-Identifier: AGPL-3.0-or-later

import type {ApiContext} from '../ApiContext';
import type * as AuthLogin from '../auth/AuthLogin';
import {loadAltarAppsAuthConfig} from './AltarAppsAuthConfig';
import {AltarAppsAuthService} from './AltarAppsAuthService';
import {AltarAppsTabletopClient} from './AltarAppsTabletopClient';

const config = loadAltarAppsAuthConfig(process.env);
const handoffs = config.enabled ? new AltarAppsTabletopClient(config) : null;

export function createAltarAppsAuthService(
	ctx: ApiContext,
	loginDependencies: AuthLogin.LoginDependencies,
): AltarAppsAuthService | null {
	if (!config.enabled || handoffs === null) {
		return null;
	}
	return new AltarAppsAuthService(ctx, loginDependencies, config, handoffs);
}
