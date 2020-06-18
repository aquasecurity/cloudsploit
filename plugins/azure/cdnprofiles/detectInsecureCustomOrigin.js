const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Detect Insecure Custom Origin',
    category: 'CDN Profiles',
    description: 'Ensures that HTTPS is enabled for CDN endpoints with a custom origin',
    more_info: 'All Azure CDN endpoints should enable HTTPS to secure traffic to the backend custom origin.',
    recommended_action: 'Enable HTTPS and disable HTTP for each custom origin endpoint for each CDN profile.',
    link: 'https://docs.microsoft.com/en-us/azure/cdn/cdn-create-endpoint-how-to',
    apis: ['profiles:list', 'endpoints:listByProfile'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
                'Secure CDN origins should be used to ensure traffic between ' +
                'the Azure CDN and backend service is encrypted.',
        pci: 'All card holder data must be transmitted over secure channels. ' +
                'Secure CDN origins should be used to ensure traffic between ' +
                'the Azure CDN and backend service is encrypted.'
    },

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
                    'Unable to query for CDN Profiles: ' + helpers.addError(profiles));
                return rcb();
            }

            if (!profiles.data.length) {
                helpers.addResult(results, 0, 'No existing CDN Profiles found', location);
                return rcb();
            }

            profiles.data.forEach(function(profile) {
                const endpoints = helpers.addSource(cache, source,
                    ['endpoints', 'listByProfile', location, profile.id]);

                if (!endpoints || endpoints.err || !endpoints.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for CDN Profile endpoints: ' + helpers.addError(endpoints), profile.id);
                } else {
                    if (!endpoints.data.length) {
                        helpers.addResult(results, 0,
                            'CDN profile does not contain any endpoints', location, profile.id);
                    } else {
                        // Loop through all endpoints
                        endpoints.data.forEach(function(endpoint) {
                            if (endpoint.isHttpAllowed) {
                                helpers.addResult(results, 2,
                                    'CDN profile endpoint allows insecure HTTP origin', location, endpoint.id);
                            } else {
                                helpers.addResult(results, 0,
                                    'CDN profile endpoint does not allow insecure HTTP origin', location, endpoint.id);
                            }
                        });
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
