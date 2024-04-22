var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Minimum TLS Version',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures Microsoft Azure PostgreSQL Servers do not allow outdated TLS certificate versions.',
    more_info: 'TLS 1.2 or higher should be used for all TLS connections to Microsoft Azure PostgreSQL server. This setting applies to all databases associated with the server.',
    recommended_action: 'Modify PostgreSQL server to use TLS version 1.2 or higher.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-tls-configurations',
    apis: ['servers:listPostgres'],
    realtime_triggers: ['microsoftdbforpostgresql:servers:write','microsoftdbforpostgresql:servers:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {
            var servers = helpers.addSource(cache, source,
                ['servers', 'listPostgres', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No PostgreSQL servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                if (!server.id) return;

                if (server.minimalTlsVersion && server.minimalTlsVersion !== 'TLSEnforcementDisabled') {
                    const tlsVersionRegex = /^TLS\d+_\d+$/;
                    if (!tlsVersionRegex.test(server.minimalTlsVersion)) {
                        helpers.addResult(results, 2, 'Postgresql server TLS version cannot be parsed', location, server.id);
                    } else {
                        var numericTlsVersion = parseFloat(server.minimalTlsVersion.replace('TLS', '').replace('_', '.'));
                        if (numericTlsVersion >= 1.2) {
                            helpers.addResult(results, 0,
                                'PostgreSQL server is using TLS version 1.2 or higher',
                                location, server.id);
                        } else {
                            helpers.addResult(results, 2,
                                'PostgreSQL server is not using TLS version 1.2',
                                location, server.id);  
                        } 
                    }
                } else {
                    helpers.addResult(results, 2,
                        'PostgreSQL server allows all TLS versions',
                        location, server.id);
                } 
                
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};