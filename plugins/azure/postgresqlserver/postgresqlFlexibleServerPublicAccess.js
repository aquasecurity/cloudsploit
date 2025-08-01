var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Flexible Server Public Access',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures that PostgreSQL flexible servers do not allow public access',
    more_info: 'Unless there is a specific business requirement, PostgreSQL flexible server instances should not have a public endpoint and should only be accessed from within a VNET.',
    recommended_action: 'Ensure that the firewall of each PostgreSQL flexible server is configured to prohibit traffic from the public 0.0.0.0 global IP address.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-firewall-rules',
    apis: ['servers:listPostgresFlexibleServer', 'firewallRules:listByFlexibleServerPostgres'],
    settings: {
        server_firewall_end_ip: {
            name: 'PostgreSQL Server Firewall Rule End IP',
            description: 'Comma separated list of IP addresses which cannot be end IPs for firewall rule',
            regex: '((25[0-5]|2[0-4]|[01]??)(25[0-5]|2[0-4]|[01]??)(25[0-5]|2[0-4]|[01]??)(25[0-5]|2[0-4]|[01]??)(,\n|,?$))',
            default: ''
        }
    },
    realtime_triggers: ['microsoftdbforpostgresql:flexibleservers:write', 'microsoftdbforpostgresql:flexibleservers:firewallrules:write', 'microsoftdbforpostgresql:flexibleservers:firewallrules:delete', 'microsoftdbforpostgresql:flexibleservers:delete'],

    run: function(cache, settings, callback) {
       
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
    
        var config = {
            server_firewall_end_ip: settings.server_firewall_end_ip || this.settings.server_firewall_end_ip.default
        };

        var checkEndIp = (config.server_firewall_end_ip.length > 0);

        async.each(locations.servers, function(location, rcb) {

            var servers = helpers.addSource(cache, source,
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

            servers.data.forEach(function(server) {
                
                if (server.network && server.network.publicNetworkAccess && server.network.publicNetworkAccess.toLowerCase() === 'disabled') {
                    helpers.addResult(results, 0, 'The PostgreSQL flexible server has public network access disabled', location, server.id);

                } else {
                    const firewallRules = helpers.addSource(cache, source,
                        ['firewallRules', 'listByFlexibleServerPostgres', location, server.id]);
    
                    if (!firewallRules || firewallRules.err || !firewallRules.data) {
                        helpers.addResult(results, 3,
                            'Unable to query PostgreSQL Flexible Server Firewall Rules: ' + helpers.addError(firewallRules), location, server.id);
                    } else {
                        if (!firewallRules.data.length) {
                            helpers.addResult(results, 0, 'No existing PostgreSQL Flexible Server Firewall Rules found', location, server.id);
                        } else {
                            var publicAccess = false;
    
                            firewallRules.data.forEach(firewallRule => {
                                console.log(firewallRule);
                                const startIpAddr = firewallRule['startIpAddress'];
                                const endIpAddr = firewallRule['endIpAddress'];
                                
                                if (startIpAddr && endIpAddr) {
                                    if (checkEndIp) {
                                        if (startIpAddr.toString().indexOf('0.0.0.0') > -1 &&
                                            config.server_firewall_end_ip.includes(endIpAddr.toString())) {
                                            publicAccess = true;
                                        }
                                    } else if (startIpAddr.toString() === '0.0.0.0' &&
                                        (endIpAddr.toString() === '255.255.255.255' || endIpAddr.toString() === '0.0.0.0')) {
                                        publicAccess = true;
                                    }

                                    // Additional check for IPv6 public access (::/0)
                                    if ((startIpAddr === '::' || startIpAddr === '::/0') && !checkEndIp) {
                                        publicAccess = true;
                                    }
                                }
                            });
    
                            if (publicAccess) {
                                helpers.addResult(results, 2, 'The PostgreSQL flexible server is open to outside traffic', location, server.id);
                            } else {
                                helpers.addResult(results, 0, 'The PostgreSQL flexible server is protected from outside traffic', location, server.id);
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