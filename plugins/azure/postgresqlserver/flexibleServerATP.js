var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Flexible Server Advanced Threat Protection',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures Advanced Threat Protection is enabled on PostgreSQL flexible servers.',
    more_info: 'Enabling Advanced Threat Protection provides security alerts on anomalous activities, allowing you to detect potential threats and respond to them as they occur.',
    recommended_action: 'Ensure Advanced Threat Protection is enabled for all PostgreSQL Flexible Servers.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-security#enable-enhanced-security-with-microsoft-defender-for-cloud',
    apis: ['servers:listPostgresFlexibleServer', 'advancedThreatProtectionSettings:listPostgresFlexibleServer'],
    realtime_triggers: ['microsoftdbforpostgresql:flexibleservers:write','microsoftdbforpostgresql:flexibleservers:delete','microsoftdbforpostgresql:flexibleservers:advancedthreatprotectionsettings:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {

            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgresFlexibleServer', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL flexible servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL flexible servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                const advancedThreatProtectionSettings = helpers.addSource(cache, source,
                    ['advancedThreatProtectionSettings', 'listPostgresFlexibleServer', location, server.id]);

                if (!advancedThreatProtectionSettings || advancedThreatProtectionSettings.err || !advancedThreatProtectionSettings.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Advanced Threat Protection settings: ' + helpers.addError(advancedThreatProtectionSettings), location, server.id);
                } else {
                    if (!advancedThreatProtectionSettings.data.length) {
                        helpers.addResult(results, 2, 'No Advanced Threat Protection setting found', location, server.id);
                    } else {
                        let atpEnabled = advancedThreatProtectionSettings.data.find(threadProtectionSetting => 
                            threadProtectionSetting.state &&
                            threadProtectionSetting.state.toLowerCase() == 'enabled');
                        if (atpEnabled) {
                            helpers.addResult(results, 0,
                                'Advanced Threat Protection is enabled for PostgreSQL flexible server', location, server.id);
                        } else {
                            helpers.addResult(results, 2,
                                'Advanced Threat Protection is disabled for PostgreSQL flexible server', location, server.id);
                        }
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
