var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Advanced Threat Protection Enabled',
    category: 'SQL Server',
    domain: 'Databases',
    description: 'Ensures that Advanced Threat Protection is enabled on SQL Servers.',
    more_info: 'Azure Defender for SQL is a unified package for advanced SQL security capabilities.',
    recommended_action: 'Ensure that ThreatDetectionState is set to Enabled',
    link: 'https://docs.microsoft.com/en-us/azure/azure-sql/database/azure-defender-for-sql',
    apis: ['servers:listSql', 'advancedThreatProtectionSettings:listByServer'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {

            var servers = helpers.addSource(cache, source,
                ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No SQL servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                const advancedThreatProtectionSettings = helpers.addSource(cache, source,
                    ['advancedThreatProtectionSettings', 'listByServer', location, server.id]);

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
                                'Advanced Threat Protection for the SQL server is enabled', location, server.id);
                        } else {
                            helpers.addResult(results, 2,
                                'Advanced Threat Protection for the SQL server is disabled', location, server.id);
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
