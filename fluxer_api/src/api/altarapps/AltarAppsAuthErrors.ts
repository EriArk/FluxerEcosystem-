// SPDX-License-Identifier: AGPL-3.0-or-later

export class AltarAppsAuthRejectedError extends Error {
	constructor() {
		super('AltarApps authentication rejected');
		this.name = 'AltarAppsAuthRejectedError';
	}
}

export class AltarAppsAuthThrottledError extends Error {
	constructor(readonly retryAfter: number) {
		super('AltarApps authentication throttled');
		this.name = 'AltarAppsAuthThrottledError';
	}
}

export class AltarAppsAuthUnavailableError extends Error {
	constructor() {
		super('AltarApps authentication unavailable');
		this.name = 'AltarAppsAuthUnavailableError';
	}
}
