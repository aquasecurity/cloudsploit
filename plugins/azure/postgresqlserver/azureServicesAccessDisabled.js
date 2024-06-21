const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Server Services Network Access Disabled',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that PostgreSQL servers do not allow access to other Azure services.',
    more_info: 'To secure your PostgreSQL server, it is recommended to disable public network access. Instead, configure firewall rules to allow connections from specific network ranges or utilize VNET rules for access from designated virtual networks. This helps prevent unauthorized access from Azure services outside your subscription.',
    recommended_action: 'Disable public network access for PostgreSQL database servers.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-firewall-rules',
    apis: ['servers:listPostgres', 'firewallRules:listByServerPostgres'],
    realtime_triggers: ['microsoftdbforpostgresql:servers:write', 'microsoftdbforpostgresql:servers:firewallrules:write','microsoftdbforpostgresql:servers:firewallrules:delete','microsoftdbforpostgresql:servers:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgres', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL servers found', location);
                return rcb();
            }

            for (let postgresServer of servers.data) {
                if (!postgresServer.id) continue;

                const firewallRules = helpers.addSource(cache, source,
                    ['firewallRules', 'listByServerPostgres', location, postgresServer.id]);

                if (!firewallRules || firewallRules.err || !firewallRules.data) {
                    helpers.addResult(results, 3,
                        'Unable to query SQL Server Firewall Rules: ' + helpers.addError(firewallRules), location, postgresServer.id);
                    continue;
                }

                if (!firewallRules.data.length) {
                    helpers.addResult(results, 0, 'No existing SQL Server Firewall Rules found', location, postgresServer.id);
                    continue;
                }

                let accessToServices =  true;
                for (let rule of firewallRules.data) {
                    if (rule.name && rule.name.toLowerCase() === 'allowallwindowsazureips') {
                        accessToServices = false;
                        break;
                    }
                }

                if (accessToServices) {
                    helpers.addResult(results, 0,
                        'Access to other Azure services is disabled for PostgreSQL server', location, postgresServer.id);
                } else {
                    helpers.addResult(results, 2,
                        'Access to other Azure services is not disabled for PostgreSQL server', location, postgresServer.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
