var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'No Public Access',
    category: 'SQL Server',
    description: 'Ensure that SQL Servers do not allow public access.',
    more_info: 'Unless there is a specific business requirement, SQL Server instances should not have a public endpoint and should only be accessed from within a VPC.',
    recommended_action: '1. Go to SQL servers 2. For each SQL server Click on Firewall / Virtual Networks 3. Ensure that the firewall rules exist, and no rule has Start IP of 0.0.0.0 and End IP of 0.0.0.0 and ensure that Allow Access to Azure Services is off.',
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
                    'Unable to query SQL Server Firewall Rules: ' + helpers.addError(firewallRules), location);
                return rcb();
            };

            if (!firewallRules.data.length) {
                helpers.addResult(results, 0, 'No existing SQL Server Firewall Rules', location);
                return rcb();
            };

            firewallRules.data.forEach(firewallRule => {
                const startIpAddr = firewallRule['startIpAddress'];
                const endIpAddr = firewallRule['endIpAddress'];
                var serverIdArr = firewallRule.id.split('/');
                serverIdArr.length = serverIdArr.length - 2;
                var serverId = serverIdArr.join('/');

                if (startIpAddr.toString().indexOf('0.0.0.0') > -1 || endIpAddr.toString().indexOf('0.0.0.0') > -1) {
                    helpers.addResult(results, 2, 'The SQL server is opened to outside network', location, serverId);
                } else {
                    helpers.addResult(results, 0, 'The SQL server is protected from outside network', location, serverId);
                };
            });
            
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};