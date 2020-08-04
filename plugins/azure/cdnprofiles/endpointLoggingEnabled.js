const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Endpoint Logging Enabled',
    category: 'CDN Profiles',
    description: 'Ensures that endpoint requests are being logged for CDN endpoints',
    more_info: 'Endpoint Logging ensures that all requests to a CDN endpoint are logged.',
    recommended_action: 'Ensure that diagnostic logging is enabled for each CDN endpoint for each CDN profile',
    link: 'https://docs.microsoft.com/en-us/azure/cdn/cdn-azure-diagnostic-logs',
    apis: ['profiles:list', 'endpoints:listByProfile', 'diagnosticSettings:listByEndpoint'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        
        async.each(locations.profiles, (location, rcb) => {
            const profiles = helpers.addSource(cache, source,
                ['profiles', 'list', location]);

            if (!profiles) return rcb();

            if (profiles.err || !profiles.data) {
                helpers.addResult(results, 3,
                    'Unable to query CDN profiles: ' + helpers.addError(profiles), location);
                return rcb();
            }

            if (!profiles.data.length) {
                helpers.addResult(results, 0, 'No existing CDN profiles found', location);
                return rcb();
            }

            profiles.data.forEach(function(profile){
                const endpoints = helpers.addSource(cache, source,
                    ['endpoints', 'listByProfile', location, profile.id]);

                if (!endpoints || endpoints.err || !endpoints.data) {
                    helpers.addResult(results, 3,
                        'Unable to query CDN endpoints: ' + helpers.addError(endpoints), location, profile.id);
                } else if (!endpoints.data.length) {
                    helpers.addResult(results, 0, 'No existing CDN endpoints found', location, profile.id);
                } else {
                    endpoints.data.forEach(function(endpoint) {
                        const diagnosticSettings = helpers.addSource(cache, source,
                            ['diagnosticSettings', 'listByEndpoint', location, endpoint.id]);

                        if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                            helpers.addResult(results, 3,
                                'Unable to query diagnostics settings: ' + helpers.addError(diagnosticSettings), location, endpoint.id);
                        } else if (!diagnosticSettings.data.length) {
                            helpers.addResult(results, 2, 'No existing diagnostics settings', location, endpoint.id);
                        } else {
                            var found = false;
                            diagnosticSettings.data.forEach(function(ds){
                                if (ds.logs && ds.logs.length) found = true;
                            });

                            if (found) {
                                helpers.addResult(results, 0, 'Request logging is enabled for endpoint', location, endpoint.id);
                            } else {
                                helpers.addResult(results, 2, 'Request logging is not enabled for endpoint', location, endpoint.id);
                            }
                        }
                    });
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};