var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Public Access',
    category: 'SQL Server',
    description: 'Ensures that SQL Servers do not allow public access',
    more_info: 'Unless there is a specific business requirement, SQL Server instances should not have a public endpoint and should only be accessed from within a VNET.',
    recommended_action: 'Ensure that the firewall of each SQL Server is configured to prohibit traffic from the public 0.0.0.0 global IP address.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-security-overview/',
    apis: ['resourceGroups:list','servers:sql:list','firewallRules:listByServer'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.firewallRules, function(location, rcb){
            var firewallRules = helpers.addSource(cache, source,
                ['firewallRules', 'listByServer', location]);

            if (!firewallRules) return rcb();

            if (firewallRules.err || !firewallRules.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL Server Firewall Rules: ' + helpers.addError(firewallRules), location);
                return rcb();
            }

            if (!firewallRules.data.length) {
                helpers.addResult(results, 0, 'No existing SQL Server Firewall Rules found', location);
                return rcb();
            }

            firewallRules.data.forEach(firewallRule => {
                const startIpAddr = firewallRule['startIpAddress'];
                const endIpAddr = firewallRule['endIpAddress'];
                var serverIdArr = firewallRule.id.split('/');
                serverIdArr.length = serverIdArr.length - 2;
                var serverId = serverIdArr.join('/');

                if (startIpAddr.toString().indexOf('0.0.0.0') > -1 || endIpAddr.toString().indexOf('0.0.0.0') > -1) {
                    helpers.addResult(results, 2, 'The SQL Server is open to outside traffic', location, serverId);
                } else {
                    helpers.addResult(results, 0, 'The SQL server is protected from outside traffic', location, serverId);
                }
            });
            
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};