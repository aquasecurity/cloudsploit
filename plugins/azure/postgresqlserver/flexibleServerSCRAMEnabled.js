const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Flexible Server SCRAM Enabled',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure PostgreSQL flexible servers are using SCRAM authentication protocol for password encryption.',
    more_info: 'Using SCRAM (Salted Challenge Response Authentication Mechanism) enhances authentication security in PostgreSQL by defending against common password-based vulnerabilities, bolstering protection against credential interception and replay attacks.',
    recommended_action: 'Modify PostgreSQL flexible server to use SCRAM for password encryption instead of MD5.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-connect-scram',
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
                    
                var configuration = configurations.data.find(config => {
                    return (config.name == 'password_encryption');
                });

                if (configuration && configuration.value && configuration.value.toUpperCase().includes('SCRAM')) {
                    helpers.addResult(results, 0, 'PostgreSQL flexible server is using SCRAM authentication protocol', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2, 'PostgreSQL flexible server is not using SCRAM authentication protocol', location, flexibleServer.id);
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};