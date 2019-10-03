var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Profile Retention Policy',
    category: 'Monitor',
    description: 'Ensure that Log Profiles have a long retention policy.',
    more_info: 'By enabling a long retention policy, Activity Logs are archived for longer than the default period of 90 days, following security and compliance best practices.',
    recommended_action: '1. Enter the Activity Log Service. 2. Select Export to Event Hub. 3. at the bottom select the retention in days, over 90 days.',
    link: 'https://docs.microsoft.com/en-us/azure/monitoring-and-diagnostics/monitoring-overview-activity-logs#export-the-activity-log-with-a-log-profile',
    apis: ['logProfiles:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var profileExists = false;

        async.each(locations.logProfiles, function(location, rcb){
            var logProfiles = helpers.addSource(cache, source,
                ['logProfiles', 'list', location]);

            if (!logProfiles) return rcb();

            if (logProfiles.err || !logProfiles.data) return rcb();
            
            if (!logProfiles.data.length) return rcb();
                
            logProfiles.data.forEach((logProfileResource) => {
                profileExists = true;
                if (logProfileResource.retentionPolicy &&
                    logProfileResource.retentionPolicy.enabled &&
                    logProfileResource.retentionPolicy.enabled == true && 
                    logProfileResource.retentionPolicy.days &&
                    logProfileResource.retentionPolicy.days > 90) {
                    helpers.addResult(results, 0, 
                        `The Log Profile has a Retention Policy of ${logProfileResource.retentionPolicy.days} days`, 
                        'global', logProfileResource.id);

                } else if (logProfileResource.retentionPolicy &&
                    logProfileResource.retentionPolicy.enabled &&
                    logProfileResource.retentionPolicy.days) {
                    helpers.addResult(results, 1, 
                        `The Log Profile does not have a long Retention Policy: ${logProfileResource.retentionPolicy.days} days`, 
                        'global', logProfileResource.id);
                        	
                } else {
                    helpers.addResult(results, 2, 
                        'The Log Profile does not have a Retention Policy', 
                        'global', logProfileResource.id);
                };
            });

            rcb();
        }, function(){
            // Global checking goes here
            if (!profileExists) {
                helpers.addResult(results, 2, 'There is no Log Profile', 'global');
            };
            callback(null, results, source);
        });
    }
};