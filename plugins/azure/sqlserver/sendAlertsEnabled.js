var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Send Alerts Enabled',
    category: 'SQL Server',
    description: 'Ensures that send alerts is enabled in advanced data security for SQL servers.',
    more_info: 'Enabling send alerts in advanced data security on all SQL servers ensures that monitored data for unusual activity, vulnerabilities, and threats get sent to the email addresses configured in advanced data protections.',
    recommended_action: 'Ensure that an email address is activated under send alerts in advanced data security for all SQL servers.',
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
                        helpers.addResult(results, 2, 'Database Threat Detection Policies are not enabled on the server', location, server.id);
                    } else {
                        serverSecurityAlertPolicies.data.forEach(serverSecurityAlertPolicy => {
                            if (serverSecurityAlertPolicy.state &&
                                serverSecurityAlertPolicy.state.toLowerCase() == 'enabled' &&
                                serverSecurityAlertPolicy.emailAddresses &&
                                serverSecurityAlertPolicy.emailAddresses[0] &&
                                serverSecurityAlertPolicy.emailAddresses[0] != '') {
                                helpers.addResult(results, 0,
                                    'Send alerts is enabled on the SQL server', location, server.id);
                            } else {
                                helpers.addResult(results, 2,
                                    'Send alerts is not enabled on the SQL server', location, server.id);
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