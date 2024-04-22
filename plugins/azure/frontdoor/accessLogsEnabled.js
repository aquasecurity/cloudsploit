const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door Access Logs Enabled',
    category: 'Front Door',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures that Azure Front Door Access Log is enabled.',
    more_info: 'Azure Front Door captures several types of logs. Access logs can be used to identify slow requests, determine error rates, and understand how Front Door\'s caching behavior is working for your solution.',
    recommended_action: 'Ensure that diagnostic setting for Front Door Access Log is enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/frontdoor/standard-premium/how-to-logs',
    apis: ['profiles:list', 'diagnosticSettings:listByAzureFrontDoor'],
    realtime_triggers: ['microsoftcdn:profiles:write', 'microsoftcdn:profiles:delete', 'microsoftinsights:diagnosticsettings:write', 'microsoftinsights:diagnosticsettings:delete'],

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
                    'Unable to query Front Door profiles: ' + helpers.addError(profiles), location);
                return rcb();
            }

            if (!profiles.data.length) {
                helpers.addResult(results, 0, 'No existing Azure Front Door profiles found', location);
                return rcb();
            }

            var frontDoorProfile = false;
            profiles.data.forEach(function(profile) {
                if (!profile.id || profile.kind!='frontdoor') return;
                
                frontDoorProfile = true;
                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByAzureFrontDoor', location, profile.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, 'Unable to query Front Door diagnostics settings: ' + helpers.addError(diagnosticSettings), location, profile.id);
                } else {
                    var frontDoorAccessLogEnabled = false;
                    diagnosticSettings.data.forEach(setting => {
                        var logs = setting.logs;
                        if (logs.some(log => (log.categoryGroup === 'audit' || log.categoryGroup === 'allLogs' || log.category === 'FrontDoorAccessLog') && log.enabled)) {
                            frontDoorAccessLogEnabled = true;
                        }
                    });
                    if (frontDoorAccessLogEnabled) {
                        helpers.addResult(results, 0, 'Front Door access logs are enabled', location, profile.id);
                    } else {
                        helpers.addResult(results, 2, 'Front Door access logs are not enabled', location, profile.id);
                    }
                }
            });

            if (!frontDoorProfile) {
                helpers.addResult(results, 0, 'No existing Azure Front Door profiles found', location);
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};