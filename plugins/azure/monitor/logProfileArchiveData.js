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

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        var logProfile;
        
        for (var location of locations.logProfiles) {

            const logProfiles = helpers.addSource(cache, source, 
                ['logProfiles', 'list', location]);

            if (!logProfiles) continue;

            if (logProfiles.err || !logProfiles.data) {
                helpers.addResult(results, 3,
                'Unable to query Log Profiles: ' + helpers.addError(logProfiles), location);
                continue;
            }
                
            if (!logProfiles.data.length) {
                continue;
            } else {
                logProfile = logProfiles.data;
                break;
            }
        }
        
        async.each(locations.logProfiles, (loc, lcb) => {
            if (!logProfile) return lcb();
            
            var logProfileMatch = logProfile.filter((d) => {
                return d.locations.includes(loc);
            });

            if (logProfileMatch.length > 0) {
                helpers.addResult(results, 0,
                'Log Profile is archiving all activities in the region.', loc);
                lcb();
            } else {
                helpers.addResult(results, 2,
                'Log Profile is not archiving data in the region.', loc);
                lcb();
            }
        }, function() {
            if (!logProfile) {
                helpers.addResult(results, 2, 'No Log Profile enabled.', 'global');
            }
            callback(null, results, source);
        });
    }
};
