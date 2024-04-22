const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL FLexible Server Log Disconnections Enabled',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures that disconnection logs are enabled for PostgreSQL flexible servers.',
    more_info: 'Enabling log_disconnections parameter records all activity data which helps in logging attempted and successful disconnections from the flexible server.',
    recommended_action: 'Ensure that server parameters for each PostgreSQL flexible server have log_disconnections setting enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-server-parameters-using-portal',
    apis: ['servers:listPostgresFlexibleServer', 'flexibleServersConfigurations:listByPostgresServer'],
    realtime_triggers: ['microsoftdbforpostgresql:flexibleservers:write','microsoftdbforpostgresql:flexibleservers:delete','microsoftdbforpostgresql:flexibleservers:configurations:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
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

            for (var flexibleServer of servers.data) {
                if (!flexibleServer.id) continue;

                const configurations = helpers.addSource(cache, source,
                    ['flexibleServersConfigurations', 'listByPostgresServer', location, flexibleServer.id]);
        
                if (!configurations || configurations.err || !configurations.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for PostgreSQL flexible server configurations: ' + helpers.addError(configurations), location, flexibleServer.id);
                    continue;
                }
                
                var configuration = configurations.data.filter(config => {
                    return (config.name == 'log_disconnections');
                });
        
                if (configuration && configuration[0] && configuration[0].value && configuration[0].value.toLowerCase() == 'on') {
                    helpers.addResult(results, 0, 'PostgreSQL flexible server has log disconnections setting enabled', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2, 'PostgreSQL flexible server does not have log disconnections setting enabled', location, flexibleServer.id);
                }

            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
