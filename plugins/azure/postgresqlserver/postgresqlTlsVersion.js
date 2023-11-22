var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Minimum TLS Version',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    description: 'Ensures Microsoft Azure PostgreSQL Servers do not allow outdated TLS certificate versions.',
    more_info: 'TLS 1.2 or higher should be used for all TLS connections to Microsoft Azure PostgreSQL server. This setting applies to all databases associated with the server.',
    recommended_action: 'Modify PostgreSQL server to set desired minimum TLS version.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-tls-configurations',
    apis: ['servers:listPostgres'],
    settings: {
        postgresql_server_min_tls_version: {
            name: 'PostgreSQL Server Minimum TLS Version',
            description: 'Minimum desired TLS version for Microsoft Azure PostgreSQL servers',
            regex: '^(1.0|1.1|1.2)$',
            default: '1.2'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        var config = {
            postgresql_server_min_tls_version: settings.postgresql_server_min_tls_version || this.settings.postgresql_server_min_tls_version.default
        };

        var desiredVersion = parseFloat(config.postgresql_server_min_tls_version);

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

                if (server.minimalTlsVersion) {
                    if (server.minimalTlsVersion === 'TLSEnforcementDisabled') {
                        helpers.addResult(results, 2,
                            'PostgreSQL server allows all TLS versions',
                            location, server.id);
                    } else {
                        var numericTlsVersion = parseFloat(server.minimalTlsVersion.replace('TLS', '').replace('_', '.'));
                        if (numericTlsVersion >= desiredVersion) {
                            helpers.addResult(results, 0,
                                `PostgreSQL server is using TLS version ${server.minimalTlsVersion} which is equal to or higher than desired TLS version ${config.postgresql_server_min_tls_version}`,
                                location, server.id);
                        } else {
                            helpers.addResult(results, 2,
                                `PostgreSQL server is using TLS version ${server.minimalTlsVersion} which is less than desired TLS version ${config.postgresql_server_min_tls_version}`,
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