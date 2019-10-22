const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
	title: 'Endpoint Logging Enabled',
	category: 'CDN Profiles',
	description: 'Ensures that endpoint requests are being logged for CDN endpoints',
	more_info: 'Endpoint Logging ensures that all requests to a CDN endpoint are logged.',
	recommended_action: 'Ensure that diagnostic logging is enabled for each CDN endpoint for each CDN profile',
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
				helpers.addResult(results, 0, 'No existing CDN endpoints found', location);
				return rcb();
			}

			if (!diagnosticSettings) return rcb();

			if (diagnosticSettings.err || !diagnosticSettings.data) {
				helpers.addResult(results, 3,
					'Unable to query diagnostics settings: ' + helpers.addError(diagnosticSettings),location);
				return rcb();
			}

			if (!diagnosticSettings.data.length) {
				helpers.addResult(results, 0, 'No existing diagnostics settings', location);
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
						'Request logging is not enabled for endpoint: ' + endpoint.name, location, endPointId);
				}
			});

			if (diagSettingFound === endpoints.data.length) {
				helpers.addResult(results, 0, 'Request logging is enabled on all endpoints', location);
			}

			rcb();
		}, function () {
			callback(null, results, source);
		});
	}
};