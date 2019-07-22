const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Profile Archive Data',
    category: 'Monitor',
    description: 'The Log Profile should be configured to export all activities from the control/management plane in all active locations.',
    more_info: 'Enabling logging of all activities in a log profile ensures that cloud security best practices, as well as compliance and monitoring standards are followed.',
    recommended_action: '1. Enter the Monitor category. 2. Select Activity Log from the left hand menu. 3. On the top of activity log select Export to Event Hub to enable activity log archiving and select the storage account or event hub to send the data to.' ,
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
                helpers.addResult(results, 1,
                'Log Profile is not archiving data in the region.', loc);
                lcb();
            }
        }, function() {
            if (!logProfile) {
                helpers.addResult(results, 2, 'No Log Profile Enabled.', 'global');
            }
            callback(null, results, source);
        });
    }
};
