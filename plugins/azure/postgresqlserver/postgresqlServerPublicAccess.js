const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Server Public Access',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures that PostgreSQL servers do not allow public access',
    more_info: 'Configuring public access for PostgreSQL server instance allows the server to be accessible through public endpoint. PostgreSQL server server instances should not have a public endpoint and should only be accessed from within a VNET.',
    recommended_action: 'Ensure that the firewall of each PostgreSQL server is configured to prohibit traffic from the public address.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/concepts-firewall-rules',
    apis: ['servers:listPostgres', 'firewallRules:listByServerPostgres'],
    settings: {
        postgresql_server_allowed_ips: {
            name: 'PostgreSQL Server Allowed IPs',
            description: 'Comma-separated list of customer defined IP addresses/ranges that are allowed to access PostgreSQL servers',
            regex: '((25[0-5]|2[0-4]|[01]??)(25[0-5]|2[0-4]|[01]??)(25[0-5]|2[0-4]|[01]??)(25[0-5]|2[0-4]|[01]??)(,\n|,?$))',
            default: ''
        }
    },
    realtime_triggers: ['microsoftdbforpostgresql:servers:write', 'microsoftdbforpostgresql:servers:firewallrules:write', 'microsoftdbforpostgresql:servers:firewallrules:delete', 'microsoftdbforpostgresql:servers:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        var config = {
            postgresql_server_allowed_ips: settings.postgresql_server_allowed_ips || this.settings.postgresql_server_allowed_ips.default
        };

        var allowedIps = [];
        if (config.postgresql_server_allowed_ips && config.postgresql_server_allowed_ips.length > 0) {
            allowedIps = config.postgresql_server_allowed_ips.split(',').map(ip => ip.trim());
        }
        var checkAllowedIps = allowedIps.length > 0;

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgres', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                if (!server.id) return;

                if (server.publicNetworkAccess && server.publicNetworkAccess.toLowerCase() === 'disabled') {
                    helpers.addResult(results, 0, 'The PostgreSQL server has public network access disabled', location, server.id);
                } else {
                    const firewallRules = helpers.addSource(cache, source,
                        ['firewallRules', 'listByServerPostgres', location, server.id]);

                    if (!firewallRules || firewallRules.err || !firewallRules.data) {
                        helpers.addResult(results, 3,
                            'Unable to query PostgreSQL Server Firewall Rules: ' + helpers.addError(firewallRules), location, server.id);
                    } else {
                        if (!firewallRules.data.length) {
                            helpers.addResult(results, 0, 'No existing PostgreSQL Server Firewall Rules found', location, server.id);
                        } else {
                            var publicAccess = false;

                            firewallRules.data.forEach(firewallRule => {
                                const startIpAddr = firewallRule['startIpAddress'];
                                const endIpAddr = firewallRule['endIpAddress'];

                                if (startIpAddr && startIpAddr.toString().indexOf('0.0.0.0') > -1) {
                                    if (checkAllowedIps) {
                                        if (endIpAddr && allowedIps.includes(endIpAddr.toString())) {
                                            publicAccess = true;
                                        }
                                    } else {
                                        if (endIpAddr && endIpAddr.toString() === '255.255.255.255') {
                                            publicAccess = true;
                                        } else if (endIpAddr && endIpAddr.toString() === '0.0.0.0') {
                                            publicAccess = true;
                                        }
                                    }
                                }
                            });

                            if (publicAccess) {
                                helpers.addResult(results, 2, 'The PostgreSQL server is open to outside traffic', location, server.id);
                            } else {
                                helpers.addResult(results, 0, 'The PostgreSQL server is protected from outside traffic', location, server.id);
                            }
                        }
                    }
                }

            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};