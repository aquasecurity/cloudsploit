var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Profile Retention Policy',
    category: 'Monitor',
    description: 'Ensures that Log Profiles have a long retention policy.',
    more_info: 'Log retention policies should be configured with sufficient retention to aid in investigation of prior security incidents and for compliance purposes.',
    recommended_action: 'Ensure that the Activity Log export to Event Hub is configured with a retention policy of at least 365 days.',
    link: 'https://docs.microsoft.com/en-us/azure/monitoring-and-diagnostics/monitoring-overview-activity-logs#export-the-activity-log-with-a-log-profile',
    apis: ['logProfiles:list'],
    compliance: {
        pci: 'PCI requires log profile retention history to be' +
            ' a minimum of 365 days.',
        hipaa: 'HIPAA requires log profile data to be archived ' +
                'for a minimum of 365 days.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        
        async.each(locations.logProfiles, (location, rcb) => {
            const logProfiles = helpers.addSource(cache, source,
                ['logProfiles', 'list', location]);

            if (!logProfiles) return rcb();

            if (logProfiles.err || !logProfiles.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Log Profiles: ' + helpers.addError(logProfiles), location);
                return rcb();
            }

            if (!logProfiles.data.length) {
                helpers.addResult(results, 2, 'No existing Log Profiles found', location);
                return rcb();
            }

            logProfiles.data.forEach(function(logProfile) {
                if (!logProfile.retentionPolicy) {
                    helpers.addResult(results, 2,
                        'The Log Profile does not have a retention policy',
                        location, logProfile.id);
                } else if (!logProfile.retentionPolicy.enabled) {
                    helpers.addResult(results, 2,
                        'The Log Profile retention policy is not enabled',
                        location, logProfile.id);
                } else if (!logProfile.retentionPolicy.days || logProfile.retentionPolicy.days < 365) {
                    helpers.addResult(results, 2,
                        `The Log Profile retention policy of ${logProfile.retentionPolicy.days || '0'} days is not sufficient (at least 365 days).`,
                        location, logProfile.id);
                } else {
                    helpers.addResult(results, 0,
                        `The Log Profile retention policy of ${logProfile.retentionPolicy.days} days is sufficient.`,
                        location, logProfile.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};