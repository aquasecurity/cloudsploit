const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Postgresql FLexible Server Connection Throttling Enabled',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures connection throttling is enabled for Postgresql flexible servers',
    more_info: 'Enabling connection_throttle.enable for PostgreSQL flexible servers mitigates the risk of brute-force attacks by temporarily blocking IP addresses with multiple failed login attempts, enhancing security and server stability.',
    recommended_action: 'Ensure the server parameters for each Postgresql flexible server have the connection_throttle.enable setting enabled.',
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
                const configurations = helpers.addSource(cache, source,
                    ['flexibleServersConfigurations', 'listByPostgresServer', location, flexibleServer.id]);
        
                if (!configurations || configurations.err || !configurations.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for configuration' + helpers.addError(configurations), location, flexibleServer.id);
                    continue;
                }
                
                var configuration = configurations.data.filter(config => {
                    return (config.name == 'connection_throttle.enable');
                });
        
                if (configuration && configuration[0].value && configuration[0].value.toLowerCase() == 'on') {
                    helpers.addResult(results, 0, 'PostgreSQL flexible server has connection throttling enabled', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2, 'PostgreSQL flexible server does not have connection throttling enabled', location, flexibleServer.id);
                }

            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
