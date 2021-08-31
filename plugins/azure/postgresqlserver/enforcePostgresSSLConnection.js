const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enforce PostgreSQL SSL Connection',
    category: 'PostgreSQL Server',
    description: 'Ensures SSL connections are enforced on PostgreSQL Servers',
    more_info: 'SSL prevents infiltration attacks by encrypting the data stream between the server and application.',
    recommended_action: 'Ensure the connection security settings of each PostgreSQL server are configured to enforce SSL connections.',
    link: 'https://docs.microsoft.com/en-us/azure/postgresql/concepts-ssl-connection-security',
    apis: ['servers:listPostgres'],
    remediation_min_version: '202101041600',
    remediation_description: 'The SSL enforcement option will be enabled for the affected PostreSQL servers',
    apis_remediate: ['servers:listPostgres'],
    actions: {remediate:['servers:update'], rollback:['servers:update']},
    permissions: {remediate: ['servers:update'], rollback: ['server:update']},
    realtime_triggers: ['microsoftdbforpostgresql:servers:write'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
            'PostgreSQL SSL connection should be used to ensure internal ' +
            'services are always connecting over a secure channel.',
    },

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
                    'Unable to query for PostgreSQL Servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Servers found', location);
                return rcb();
            }

            for (let res in servers.data) {
                const postgresServer = servers.data[res];

                if (postgresServer.sslEnforcement &&
                    postgresServer.sslEnforcement.toLowerCase() == 'enabled') {
                    helpers.addResult(results, 0,
                        'The PostgreSQL Server is configured to enforce SSL connections', location, postgresServer.id);
                } else {
                    helpers.addResult(results, 2,
                        'The PostgreSQL Server is not configured to enforce SSL connections', location, postgresServer.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;

        // inputs specific to the plugin
        var pluginName = 'enforcePostgresSSLConnection';
        var baseUrl = 'https://management.azure.com{resource}?api-version=2017-12-01';
        var method = 'PATCH';

        // for logging purposes
        var serverNameArr = resource.split('/');
        var serverName = serverNameArr[serverNameArr.length - 1];

        // create the params necessary for the remediation
        if (settings.region) {
            var body = {
                'properties': {
                    'sslEnforcement': 'Enabled'
                }
            };

            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                'SSLEnforcement': 'Disabled',
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
