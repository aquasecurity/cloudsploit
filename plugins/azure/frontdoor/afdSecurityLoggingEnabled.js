const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door Security Logging Enabled',
    category: 'Front Door',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures that Azure Front Door Access and WAF logs are enabled.',
    more_info: 'Azure Front Door captures several types of logs. Access logs can be used to identify slow requests, determine error rates, and understand how Front Door\'s caching behavior is working for your solution. Web application firewall (WAF) logs can be used to detect potential attacks, and false positive detections that might indicate legitimate requests that the WAF blocked.',
    recommended_action: 'Modify Front Door profile and add diagnostic settings for Access and WAF Logs.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-monitor?pivots=front-door-standard-premium',
    apis: ['profiles:list', 'diagnosticSettings:listByAzureFrontDoor'],
    realtime_triggers: ['microsoftcdn:profiles:write', 'microsoftcdn:profiles:delete' , 'microsoftinsights:diagnosticsettings:write', 'microsoftinsights:diagnosticsettings:delete'],

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
                if (!profile.id || profile.kind != 'frontdoor') return;

                frontDoorProfile = true;
                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByAzureFrontDoor', location, profile.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, 'Unable to query Front Door diagnostics settings: ' + helpers.addError(diagnosticSettings), location, profile.id);
                } else {
                    var missingLogs = ['FrontDoorAccessLog', 'FrontDoorWebApplicationFirewallLog'];
                    diagnosticSettings.data.forEach(settings => {
                        const logs = settings.logs;
                        missingLogs = missingLogs.filter(requiredCategory =>
                            !logs.some(log => (log.category === requiredCategory && log.enabled) || log.categoryGroup === 'allLogs' && log.enabled)
                        );
                    });

                    if (missingLogs.length) {
                        helpers.addResult(results, 2, `Front Door profile does not have security logging enabled. Missing Logs ${missingLogs}`, location, profile.id);
                    } else {
                        helpers.addResult(results, 0, 'Front Door profile has security logging enabled', location, profile.id);
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