const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
	title: 'Endpoint Logging Enabled',
	category: 'CDN profiles',
	description: 'Ensures that endpoint requests are being logged properly.',
	more_info: 'Enabling Endpoint Logging records all requests on a CDN endpoint, following compliance standards and ensuring that security best practices are being followed.',
	recommended_action: '1. Navigate to CDN profiles. 2. Select a profile. 3. Select an endpoint. 4. Select the Diagnostics Logs blade under Monitoring. 5. Ensure at least one of the log settings is selected to enable logging on the endpoint.',
	link: 'https://docs.microsoft.com/en-us/azure/cdn/cdn-azure-diagnostic-logs',
	apis: ['resourceGroups:list', 'diagnosticSettingsOperations:list', 'profiles:list', 'endpoints:listByProfile'],

	run: function (cache, settings, callback) {
		const results = [];
		const source = {};
		const locations = helpers.locations(settings.govcloud);

		async.each(locations.endpoints, (location, rcb) => {

			const diagnosticSettings = helpers.addSource(cache, source, 
				['diagnosticSettingsOperations', 'list', location]);

			const endpoints = helpers.addSource(cache, source, 
				['endpoints', 'listByProfile', location]);

			if (!endpoints) return rcb();

			if (endpoints.err || !endpoints.data) {
				helpers.addResult(results, 3,
					'Unable to query CDN endpoints: ' + helpers.addError(endpoints), location);
				return rcb();
			}

			if (!endpoints.data.length) {
				helpers.addResult(results, 0, 'No existing CDN Endpoints', location);
				return rcb();
			}

			if (!diagnosticSettings) return rcb();

			if (diagnosticSettings.err || !diagnosticSettings.data) {
				helpers.addResult(results, 3,
					'Unable to query Diagnostics settings: ' + helpers.addError(diagnosticSettings),location);
				return rcb();
			}

			if (!diagnosticSettings.data.length) {
				helpers.addResult(results, 0, 'No existing Diagnostics settings', location);
				return rcb();
			}

			let diagSettingFound = 0;

			endpoints.data.forEach(endpoint => {

				const endPointId = endpoint.id;

				const diagnosticSetting = diagnosticSettings.data.find(diagSetting => {
					if (diagSetting.id === endPointId && 
						diagSetting.value && 
						diagSetting.value.length) {

						const logs = diagSetting.value.find(diagSettingVal => {
							if (diagSettingVal.logs && 
								diagSettingVal.logs.length && 
								diagSettingVal.logs[0].enabled) {
								return true;
							} else {
								return false;
							}
						});
						if (logs) return true;
					}
					return false
				});
				if (diagnosticSetting) {
					diagSettingFound += 1;
				} else {
					helpers.addResult(results, 2,
						'Request Logging is not Enabled on Endpoint', location, endpoint.name);
				}
			});

			if (diagSettingFound === endpoints.data.length) {
				helpers.addResult(results, 0, 'Request Logging is Enabled on All Endpoints', location);
			}

			rcb();
		}, function () {
			callback(null, results, source);
		});
	}
};