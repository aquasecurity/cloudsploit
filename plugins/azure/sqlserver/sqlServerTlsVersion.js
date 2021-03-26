var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Minimum TLS Version',
    category: 'SQL Server',
    description: 'Ensures Microsoft Azure SQL Servers do not allow outdated TLS certificate versions.',
    more_info: 'TLS 1.2 or higher should be used for all TLS connections to Microsoft Azure SQL server. This setting applies to all databases associated with the server.',
    recommended_action: 'Modify SQL server firewall and virtual network settings to set desired minimum TLS version.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings#minimal-tls-version',
    apis: ['servers:listSql'],
    settings: {
        sql_server_min_tls_version: {
            name: 'SQL Server Minimum TLS Version',
            description: 'Minimum desired TLS version for Microsoft Azure SQL servers',
            regex: '^(1.0|1.1|1.2)$',
            default: '1.2'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        var config = {
            sql_server_min_tls_version: settings.sql_server_min_tls_version || this.settings.sql_server_min_tls_version.default
        };

        var desiredVersion = parseFloat(config.sql_server_min_tls_version);

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
                if (!server.id) return;

                if (server.minimalTlsVersion &&
                    parseFloat(server.minimalTlsVersion) >= desiredVersion) {
                    helpers.addResult(results, 0,
                        `SQL server is using TLS version ${server.minimalTlsVersion} which is equal to or higher than desired TLS version ${config.sql_server_min_tls_version}`,
                        location, server.id);
                } else {
                    helpers.addResult(results, 2,
                        `SQL server is using TLS version ${server.minimalTlsVersion} which is less than desired TLS version ${config.sql_server_min_tls_version}`,
                        location, server.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};