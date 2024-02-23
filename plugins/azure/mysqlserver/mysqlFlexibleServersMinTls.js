const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'MySQL Flexible Server Minimum TLS Version',
    category: 'MySQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure TLS version on MySQL flexible servers is set to the default value.',
    more_info: 'TLS connectivity helps to provide a new layer of security by connecting database server to client applications using Transport Layer Security (TLS). Enforcing TLS connections between database server and client applications helps protect against "man in the middle" attacks by encrypting the data stream between the server and application.',
    recommended_action: 'Modify MySQL flexible server tls_version parameter and set to desired minimum TLS version.',
    link: 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-connect-tls-ssl',
    apis: ['servers:listMysqlFlexibleServer', 'flexibleServersConfigurations:listByServer'],   
    realtime_triggers: ['microsoftdbformysql:flexibleservers:write','microsoftdbformysql:flexibleservers:configurations:write','microsoftdbformysql:flexibleservers:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listMysqlFlexibleServer', location]);

            if (!servers) return rcb();
                
            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for MySQL flexible servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing MySQL flexible servers found', location);
                return rcb();
            }

            for (var flexibleServer of servers.data) {
                const configurations = helpers.addSource(cache, source,
                    ['flexibleServersConfigurations', 'listByServer', location, flexibleServer.id]);

                if (!configurations || configurations.err || !configurations.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for  ' + helpers.addError(configurations), location, flexibleServer.id);
                    continue;
                }
                    
                var configuration = configurations.data.filter(config => {
                    return (config.name == 'tls_version');
                });

                var tls_versions =  configuration && configuration[0] && configuration[0].value ? configuration[0].value.toUpperCase().split(','): '';

                if (tls_versions.includes('TLSV1') || tls_versions.includes('TLSV1.1')) {
                    helpers.addResult(results, 2, 'MySQL flexible server is not using latest TLS version', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 0, 'MySQL flexible server is using latest TLS version', location, flexibleServer.id);
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};