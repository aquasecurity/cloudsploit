var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Public Access',
    category: 'SQL Server',
    description: 'Ensures that SQL Servers do not allow public access',
    more_info: 'Unless there is a specific business requirement, SQL Server instances should not have a public endpoint and should only be accessed from within a VNET.',
    recommended_action: 'Ensure that the firewall of each SQL Server is configured to prohibit traffic from the public 0.0.0.0 global IP address.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-security-overview/',
    apis: ['servers:listSql','firewallRules:listByServer'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

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
                const firewallRules = helpers.addSource(cache, source,
                    ['firewallRules', 'listByServer', location, server.id]);

                if (!firewallRules || firewallRules.err || !firewallRules.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Database Threat Detection Policies: ' + helpers.addError(firewallRules), location, server.id);
                } else {
                    if (!firewallRules.data.length) {
                        helpers.addResult(results, 0, 'No existing SQL Server Firewall Rules found', location, server.id);
                    } else {
                        var publicAccess = false;

                        firewallRules.data.forEach(firewallRule => {
                            const startIpAddr = firewallRule['startIpAddress'];
                            const endIpAddr = firewallRule['endIpAddress'];

                            if (startIpAddr && startIpAddr.toString().indexOf('0.0.0.0') > -1) {
                                publicAccess = true;
                            } else if (endIpAddr && endIpAddr.toString().indexOf('0.0.0.0') > -1) {
                                publicAccess = true;
                            }
                        });

                        if (publicAccess) {
                            helpers.addResult(results, 2, 'The SQL Server is open to outside traffic', location, server.id);
                        } else {
                            helpers.addResult(results, 0, 'The SQL server is protected from outside traffic', location, server.id);
                        }
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