var expect = require('chai').expect;
var postgresqlFlexibleServerPublicAccess = require('./postgresqlFlexibleServerPublicAccess');

const listPostgresFlexibleServer = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server",
        "type": "Microsoft.DBforPostgreSQL/flexibleServers",
        "network": {
            "publicNetworkAccess": "Disabled"
        }
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server-2",
        "type": "Microsoft.DBforPostgreSQL/flexibleServers",
        "network": {
            "publicNetworkAccess": "Enabled"
        }
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server-3",
        "type": "Microsoft.DBforPostgreSQL/flexibleServers"
    }
];

const firewallRules = [
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server/firewallRules/AllowAll",
        "name": "AllowAll",
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server/firewallRules/AllowAllAlt",
        "name": "AllowAllAlt",
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "0.0.0.0"
    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server/firewallRules/AllowIPv6",
        "name": "AllowIPv6",
        "startIpAddress": "::",
        "endIpAddress": "::"
    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server/firewallRules/AllowIPv6Alt",
        "name": "AllowIPv6Alt",
        "startIpAddress": "::/0",
        "endIpAddress": "::/0"
    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server/firewallRules/RestrictedIP",
        "name": "RestrictedIP",
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "192.168.1.1"
    }
];

const createCache = (servers, rules1) => {
    const serverId1 = (servers && servers.length > 0) ? servers[0].id : null;

    const cache = {
        servers: {
            listPostgresFlexibleServer: {
                'eastus': {
                    data: servers
                }
            }
        },
        firewallRules: {
            listByFlexibleServerPostgres: {
                'eastus': {}
            }
        }
    };

    if (serverId1) {
        cache.firewallRules.listByFlexibleServerPostgres.eastus[serverId1] = {
            data: rules1 || []
        };
    }

    return cache;
};

describe('postgresqlFlexibleServerPublicAccess', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL flexible servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([]);
            postgresqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if server has public network access disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The PostgreSQL flexible server has public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresFlexibleServer[0]]);
            postgresqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if server has public access enabled but no firewall rules', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL Flexible Server Firewall Rules found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresFlexibleServer[1]], []);
            postgresqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give failing result if server has firewall rule with restricted end IP', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The PostgreSQL flexible server is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresFlexibleServer[1]], [firewallRules[4]]);
            postgresqlFlexibleServerPublicAccess.run(cache, {server_firewall_end_ip: '192.168.1.1'}, callback);
        });

        it('should give failing result if server has firewall rule allowing 0.0.0.0/0 access (full range)', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The PostgreSQL flexible server is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresFlexibleServer[1]], [firewallRules[0]]);
            postgresqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give failing result if server has firewall rule allowing 0.0.0.0/0 access (0.0.0.0-0.0.0.0)', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The PostgreSQL flexible server is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresFlexibleServer[1]], [firewallRules[1]]);
            postgresqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for PostgreSQL Servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for PostgreSQL flexible servers');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = {
                servers: {
                    listPostgresFlexibleServer: {
                        'eastus': {
                            err: 'Error querying servers'
                        }
                    }
                }
            };

            postgresqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query firewall rules', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query PostgreSQL Flexible Server Firewall Rules');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = {
                servers: {
                    listPostgresFlexibleServer: {
                        'eastus': {
                            data: [listPostgresFlexibleServer[1]]
                        }
                    }
                },
                firewallRules: {
                    listByFlexibleServerPostgres: {
                        'eastus': {
                            [listPostgresFlexibleServer[1].id]: {
                                err: 'Error querying firewall rules'
                            }
                        }
                    }
                }
            };

            postgresqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });
    });
});