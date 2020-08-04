var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Advanced Data Security Enabled',
    category: 'SQL Server',
    description: 'Ensures that Advanced Data Security is enabled for SQL Servers',
    more_info: 'Enabling Advanced Data Security on all SQL Servers ensures that SQL server data is encrypted and monitored for unusual activity, vulnerabilities, and threats.',
    recommended_action: 'Ensure that Advanced Data Security is enabled for all SQL Servers.',
    link: 'https://docs.microsoft.com/en-gb/azure/sql-database/sql-database-advanced-data-security',
    apis: ['servers:listSql', 'serverSecurityAlertPolicies:listByServer'],

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
                const serverSecurityAlertPolicies = helpers.addSource(cache, source,
                    ['serverSecurityAlertPolicies', 'listByServer', location, server.id]);

                if (!serverSecurityAlertPolicies || serverSecurityAlertPolicies.err || !serverSecurityAlertPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Database Threat Detection Policies: ' + helpers.addError(serverSecurityAlertPolicies), location, server.id);
                } else {
                    if (!serverSecurityAlertPolicies.data.length) {
                        helpers.addResult(results, 2, 'No Database Threat Detection policies found', location, server.id);
                    } else {
                        serverSecurityAlertPolicies.data.forEach(serverSecurityAlertPolicy => {
                            if (serverSecurityAlertPolicy.state &&
                                serverSecurityAlertPolicy.state.toLowerCase() == 'enabled') {
                                helpers.addResult(results, 0,
                                    'Advanced Data Security for the SQL server is enabled', location, server.id);
                            } else {
                                helpers.addResult(results, 2,
                                    'Advanced Data Security for the SQL server is disabled', location, server.id);
                            }
                        });
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};