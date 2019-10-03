var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Advanced Data Security Enabled',
    category: 'SQL Server',
    description: 'Ensure that Advanced Data Security is set to on for SQL server.',
    more_info: 'Enabling Advanced Data Security on all SQL servers ensures that SQL server data is not only encrypted but also monitors for unusual activities, vulnerabilities, and threats.',
    recommended_action: '1. Go to SQL server. 2. For each server instance click on Advanced Data Security. 3. Ensure that Advanced Data Security is set to on.',
    link: 'https://docs.microsoft.com/en-gb/azure/sql-database/sql-database-advanced-data-security',
    apis: ['resourceGroups:list', 'servers:listByResourceGroup', 'serverSecurityAlertPolicies:listByServer'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.serverSecurityAlertPolicies, function (location, rcb) {

            const serverSecurityAlertPolicies = helpers.addSource(cache, source,
                ['serverSecurityAlertPolicies', 'listByServer', location]);

            if (!serverSecurityAlertPolicies) return rcb();

            if (serverSecurityAlertPolicies.err || !serverSecurityAlertPolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to query Database Threat Detection Policies: ' + helpers.addError(serverSecurityAlertPolicies), location);
                return rcb();
            };

            if (!serverSecurityAlertPolicies.data.length) {
                helpers.addResult(results, 0, 'No database Threat Detection policies found', location);
                return rcb();
            };

            serverSecurityAlertPolicies.data.forEach(serverSecurityAlertPolicy => {
                var serverIdArr = serverSecurityAlertPolicy.id.split('/');
                serverIdArr.length = serverIdArr.length - 2;
                var serverId = serverIdArr.join('/');
                
                if (serverSecurityAlertPolicy.state &&
                    serverSecurityAlertPolicy.state == 'Enabled') {
                    helpers.addResult(results, 0,
                        'Advanced Data security for the SQL server is enabled.', location, serverId);
                } else if (serverSecurityAlertPolicy.state &&
                        serverSecurityAlertPolicy.state == 'Disabled') {
                    helpers.addResult(results, 2,
                        'Advanced Data security for the SQL server is disabled.', location, serverId);
                };
            });
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};