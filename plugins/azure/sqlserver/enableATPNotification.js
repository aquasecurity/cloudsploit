var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Advanced Threat Protection Notification Enabled',
    category: 'SQL Server',
    domain: 'Databases',
    description: 'Ensures that Advanced Threat Protection Notification alert is enabled on SQL Servers.',
    more_info: 'Advanced Threat Protection for Azure SQL Database detects anomalous activities indicating unusual and potentially harmful attempts to access or exploit databases. Advanced Threat Protection can identify Potential SQL injection, Access from unusual location or data center, Access from unfamiliar principal or potentially harmful application, and Brute force SQL credentials.',
    recommended_action: 'Ensure that advanced threat protection email Notifications are configured',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/threat-detection-configure?view=azuresql',
    apis: ['servers:listSql','securityContactv2:listAll','advancedThreatProtectionSettings:listByServer'],

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
            var securityContacts = helpers.addSource(cache, source,
                ['securityContactv2', 'listAll', 'global']);

            let notifyEnabled = securityContacts && securityContacts.data && securityContacts.data.find(contact => contact.alertNotifications && contact.alertNotifications.state && contact.alertNotifications.state.toLowerCase() == 'on');
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

                            if (notifyEnabled) {
                                helpers.addResult(results, 0,
                                    'Advanced Threat Protection Notification for the SQL server is enabled', location, server.id);
                            } else {
                                helpers.addResult(results, 2,
                                    'Advanced Threat Protection Notification for the SQL server is disbaled', location, server.id);
                            }
                            
                        } else {
                            helpers.addResult(results, 0,
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
