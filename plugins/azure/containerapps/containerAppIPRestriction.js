var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Container Apps IP Restriction Configured',
    category: 'Container Apps',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures that Container Apps are configured to allow only specific IP addresses.',
    more_info: 'Azure Container Apps provides IP ingress restrictions for controlling inbound traffic, enhancing application security. Allow or deny rules can be defined for specific IP ranges, enabling precise access management to container apps. This feature is crucial for reducing potential security vulnerabilities, as unrestricted configurations permit all inbound traffic by default.'
    recommended_action: 'Modify Container Apps and configure IP restriction.',
    link: 'https://learn.microsoft.com/en-us/azure/container-apps/ip-restrictions',
    apis: ['containerApps:list'],
    realtime_triggers: ['microsoftapp:containerapps:write', 'microsoftapp:containerapps:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.containerApps, function(location, rcb) {
            var containerApps = helpers.addSource(cache, source,
                ['containerApps', 'list', location]);

            if (!containerApps) return rcb();

            if (containerApps.err || !containerApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Container apps: ' + helpers.addError(containerApps), location);
                return rcb();
            }

            if (!containerApps.data.length) {
                helpers.addResult(results, 0, 'No existing Container apps found', location);
                return rcb();
            }

            for (let container of containerApps.data) {
                if (!container.id) continue;
                if (container.configuration && container.configuration.ingress && container.configuration.ingress.ipSecurityRestrictions && container.configuration.ingress.ipSecurityRestrictions.length) {
                    helpers.addResult(results, 0,
                        'Container app has IP restrictions configured', location, container.id);
                    
                } else {
                    helpers.addResult(results, 2,
                        'Container app does not have IP restrictions configured', location, container.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

