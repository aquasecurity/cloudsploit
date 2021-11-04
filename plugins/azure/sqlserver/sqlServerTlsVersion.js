var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Minimum TLS Version',
    category: 'SQL Server',
    domain: 'Databases',
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
    remediation_min_version: '202104012200',
    remediation_description: 'TLS version 1.2 will be set for the affected SQL server',
    apis_remediate: ['servers:listSql'],
    actions: {remediate:['servers:update'], rollback:['servers:update']},
    permissions: {remediate: ['servers:update'], rollback: ['servers:update']},
    realtime_triggers: ['microsoftsql:servers:write'],

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

                if (server.minimalTlsVersion) {
                    if (parseFloat(server.minimalTlsVersion) >= desiredVersion) {
                        helpers.addResult(results, 0,
                            `SQL server is using TLS version ${server.minimalTlsVersion} which is equal to or higher than desired TLS version ${config.sql_server_min_tls_version}`,
                            location, server.id);
                    } else {
                        helpers.addResult(results, 2,
                            `SQL server is using TLS version ${server.minimalTlsVersion} which is less than desired TLS version ${config.sql_server_min_tls_version}`,
                            location, server.id);   
                    }
                } else {
                    helpers.addResult(results, 2,
                        'SQL server allows all TLS versions',
                        location, server.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;

        // inputs specific to the plugin
        var pluginName = 'sqlServerTlsVersion';
        var baseUrl = 'https://management.azure.com/{resource}?api-version=2020-08-01-preview';
        var method = 'PATCH';

        // for logging purposes
        var serverNameArr = resource.split('/');
        var serverName = serverNameArr[serverNameArr.length - 1];

        // create the params necessary for the remediation
        if (settings.region) {
            var body = {
                'location': settings.region,
                'properties': {
                    'minimalTlsVersion': '1.2'
                }
            };

            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                'TLS1.2': 'Disabled',
                'Server': serverName
            };

            helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
                if (err) return callback(err);
                if (action) action.action = putCall;


                remediation_file['post_remediate']['actions'][pluginName][resource] = action;
                remediation_file['remediate']['actions'][pluginName][resource] = {
                    'Action': 'Enabled'
                };

                callback(null, action);
            });
        } else {
            callback('No region found');
        }
    }
};