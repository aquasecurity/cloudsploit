const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Solution Logging',
    category: 'Log Alerts',
    description: 'Ensures Activity Log Alerts for the create or update and delete Security Solution events are enabled',
    more_info: 'Monitoring for create or update and delete Security Solution events gives insight into event changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Security Solution create or update and delete events.',
    link: 'https://docs.microsoft.com/en-us/azure/security/azure-log-audit',
    apis: ['resourceGroups:list', 'activityLogAlerts:listByResourceGroup'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, (location, rcb) => {
            const activityLogAlerts = helpers.addSource(cache, source, 
                ['activityLogAlerts', 'listByResourceGroup', location]);

        if (!activityLogAlerts) return rcb();

        if (activityLogAlerts.err || !activityLogAlerts.data) {
            helpers.addResult(results, 3,
                'Unable to query for Log Alerts: ' + helpers.addError(activityLogAlerts), location);
            return rcb();
        }

        if (!activityLogAlerts.data.length) {
            helpers.addResult(results, 2, 'No existing Log Alerts found', location);
            return rcb();
        }

        var writeExists = false;
        var deleteExists = false;

        activityLogAlerts.data.forEach(activityLogAlertResource => {
            const allConditions = activityLogAlertResource.condition;

            for (var allCondition of allConditions.allOf) {
                const condition = allCondition.equals;
                if (condition && condition.indexOf("microsoft.security/securitysolutions/write") > -1) {
                    helpers.addResult(results, 0,
                        'Log Alert for Security Solution write is enabled', location, activityLogAlertResource.id);
                    writeExists = true;
                }
                if (condition && condition.indexOf("microsoft.security/securitysolutions/delete") > -1) {
                    helpers.addResult(results, 0,
                        'Log Alert for Security Solution delete is enabled', location, activityLogAlertResource.id);
                    deleteExists = true;
                }

                if (writeExists && deleteExists) break;
            };
        });

        if (!writeExists) {
            helpers.addResult(results, 2,
                'Log Alert for Security Solution write is not enabled', location);
        }

        if (!deleteExists) {
            helpers.addResult(results, 2,
                'Log Alert for Security Solution delete is not enabled', location);   
        }

        rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
