const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Profile Archive Data',
    category: 'Monitor',
    description: 'Ensures the Log Profile is configured to export all activities from the control and management planes in all active locations',
    more_info: 'Exporting log activity for control plane activity allows for audited access to the Azure account with event data in the case of a security incident.',
    recommended_action: 'Ensure that all activity is logged to the Event Hub or storage account for archiving.' ,
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/archive-activity-log',
    apis: ['logProfiles:list'],
    compliance: {
        hipaa: 'HIPAA has clearly defined audit requirements for environments ' +
            'containing sensitive data. Log Profiles are the recommended ' +
            'logging and auditing solution for Azure since it is tightly ' +
            'integrated into most Azure services and APIs.',
        pci: 'Log profiles satisfy the PCI requirement to log all account activity ' +
            'within environments containing cardholder data.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

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

            logProfiles.data.forEach(function(logProfile){
                var issues = [];
                if (logProfile.locations && logProfile.locations.length) {
                    var unmatchedRegions = [];
                    locations.all.forEach(function(region){
                        if (region !== 'global' && logProfile.locations.indexOf(region) === -1) {
                            unmatchedRegions.push(region);
                        }
                    });
                    if (unmatchedRegions.length) {
                        issues.push('the following regions are not being monitored: ' + unmatchedRegions.join(', '));
                    }
                } else {
                    issues.push('no regions are being monitored');
                }

                if (logProfile.categories && logProfile.categories.length) {
                    var unmatchedCats = [];
                    ['Write', 'Delete', 'Action'].forEach(function(cat){
                        if (logProfile.categories.indexOf(cat) === -1) {
                            unmatchedCats.push(cat);
                        }
                    });
                    if (unmatchedCats.length) {
                        issues.push('the following categories are not being monitored: ' + unmatchedCats.join(', '));
                    }
                } else {
                    issues.push('no log categories are being monitored');
                }

                if (issues.length) {
                    helpers.addResult(results, 2,
                        'Log Profile has the following issues: ' + issues.join('; '), location, logProfile.id);
                } else {
                    helpers.addResult(results, 0,
                        'Log Profile is archiving all activities in all regions.', location, logProfile.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
