const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door WAF Logs Enabled',
    category: 'Front Door',
    domain: 'Content Delivery',
    description: 'Ensures that Azure Front Door WAF logs are enabled.',
    more_info: 'Azure Front Door captures several types of logs. Web application firewall (WAF) logs can be used to detect potential attacks, and false positive detections that might indicate legitimate requests that the WAF blocked.',
    recommended_action: 'Ensure that diagnostic setting for Front Door WAF logs is enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/frontdoor/standard-premium/how-to-logs',
    apis: ['profiles:list', 'diagnosticSettings:listByAzureFrontDoor'],

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
                    var frontDoorWafLogsEnabled = false;
                    diagnosticSettings.data.forEach(setting => {
                        var logs = setting.logs;
                        if (logs.some(log => (log.categoryGroup === 'allLogs' || log.category === 'FrontDoorWebApplicationFirewallLog') && log.enabled)) {
                            frontDoorWafLogsEnabled = true;
                        }
                    });
                 if (frontDoorWafLogsEnabled) {
                        helpers.addResult(results, 0, 'Front Door profile WAF logs are enabled', location, profile.id);
                    } else {
                        helpers.addResult(results, 2, 'Front Door profile WAF logs are not enabled', location, profile.id);
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