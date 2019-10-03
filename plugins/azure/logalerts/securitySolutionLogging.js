const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Solution Logging',
    category: 'Log Alerts',
    description: 'Ensure an Activity Log Alert for the Create or Update Security Solution and Delete Security Solution events are enabled.',
    more_info: 'Monitoring for Create or Update Security Solution and Delete Security Solution Rules events gives insight into network access changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: '1. Enter the Alerts service. 2. Select the Add Activity Log Alert button at the top of the page. 3. In Criteria, Select Security in the Event Category and Create or Update Security Solution in Operation Name 4. Go back and Add Delete Security Solution in Operation Name.',
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
                'Unable to query Log Alerts: ' + helpers.addError(activityLogAlerts), location);
            return rcb();
        };

        if (!activityLogAlerts.data.length) {
            helpers.addResult(results, 1, 'No existing Log Alerts', location);
            return rcb();
        };

        var writeExists = false;
        var deleteExists = false;

        activityLogAlerts.data.forEach(activityLogAlertResource => {
            const allConditions = activityLogAlertResource.condition;

            for (var allCondition of allConditions.allOf) {
                const condition = allCondition.equals;
                if (condition.indexOf("microsoft.security/securitysolutions/write") > -1) {
                    writeExists = true;
                };
                if (condition.indexOf("microsoft.security/securitysolutions/delete") > -1) {
                    deleteExists = true;
                };

                if (writeExists && deleteExists) break;
            };
        });

        if (writeExists) {
            helpers.addResult(results, 0,
                'Log Alert for Create or Update Security Solution is enabled', location);
        } else {
            helpers.addResult(results, 2,
                'Log Alert for Create or Update Security Solution is not enabled', location);
        };

        if (deleteExists) {
            helpers.addResult(results, 0,
                'Log Alert for Delete Security Solution is enabled', location);
        } else {
            helpers.addResult(results, 2,
                'Log Alert for Delete Security Solution is not enabled', location);
        };

        rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
