const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enforce MySQL SSL Connection',
    category: 'MySQL Server',
    domain: 'Databases',
    description: 'Ensures SSL connection is enforced on MySQL servers',
    more_info: 'MySQL servers should be set to use SSL for data transmission to ensure all data is encrypted in transit.',
    recommended_action: 'Ensure the connection security of each Azure Database for MySQL is configured to enforce SSL connections.',
    link: 'https://docs.microsoft.com/en-us/azure/mysql/concepts-ssl-connection-security',
    apis: ['servers:listMysql'],
    remediation_min_version: '202103302200',
    remediation_description: 'The SSL enforcement option will be enabled for the affected MySQL servers',
    apis_remediate: ['servers:listMysql'],
    actions: {remediate:['servers:update'], rollback:['servers:update']},
    permissions: {remediate: ['servers:update'], rollback: ['server:update']},
    realtime_triggers: ['microsoftdbformysql:servers:write'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
            'MySQL SSL connection should be used to ensure internal ' +
            'services are always connecting over a secure channel.',
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {

            const servers = helpers.addSource(cache, source,
                ['servers', 'listMysql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for MySQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing MySQL servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                if (server.sslEnforcement &&
                    server.sslEnforcement.toLowerCase() == 'enabled') {
                    helpers.addResult(results, 0,
                        'The MySQL server enforces SSL connections', location, server.id);
                } else {
                    helpers.addResult(results, 2,
                        'The MySQL server does not enforce SSL connections', location, server.id);
                } 
            });

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
        var pluginName = 'enforceMySQLSSLConnection';
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