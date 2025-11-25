var expect = require('chai').expect;
var postgresqlServerPublicAccess = require('./postgresqlServerPublicAccess');

const listPostgresServer = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/servers/test-server",
        "type": "Microsoft.DBforPostgreSQL/servers",
        "publicNetworkAccess": "Disabled"
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/servers/test-server-2",
        "type": "Microsoft.DBforPostgreSQL/servers",
        "publicNetworkAccess": "Enabled"
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/servers/test-server-3",
        "type": "Microsoft.DBforPostgreSQL/servers"
    }
];

const firewallRules = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/servers/test-server/firewallRules/TestRule",
        "name": "TestRule",
        "type": "Microsoft.DBforPostgreSQL/servers/firewallRules",
        "startIpAddress": "192.168.1.1",
        "endIpAddress": "192.168.1.10"
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/servers/test-server/firewallRules/AllowAll",
        "name": "AllowAll",
        "type": "Microsoft.DBforPostgreSQL/servers/firewallRules",
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/servers/test-server/firewallRules/AllowAllAlt",
        "name": "AllowAllAlt",
        "type": "Microsoft.DBforPostgreSQL/servers/firewallRules",
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "0.0.0.0"
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/servers/test-server/firewallRules/CustomerIP",
        "name": "CustomerIP",
        "type": "Microsoft.DBforPostgreSQL/servers/firewallRules",
        "startIpAddress": "10.0.0.1",
        "endIpAddress": "10.0.0.1"
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/servers/test-server/firewallRules/AllowAllWindowsAzureIPs",
        "name": "AllowAllWindowsAzureIPs",
        "type": "Microsoft.DBforPostgreSQL/servers/firewallRules",
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "0.0.0.0"
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/servers/test-server/firewallRules/CustomerDefinedRule",
        "name": "CustomerDefinedRule",
        "type": "Microsoft.DBforPostgreSQL/servers/firewallRules",
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "10.0.0.1"
    }
];

const createCache = (servers, rules1, rules2) => {
    const serverId1 = (servers && servers.length > 0) ? servers[0].id : null;
    const serverId2 = (servers && servers.length > 1) ? servers[1].id : null;

    const cache = {
        servers: {
            listPostgres: {
                'eastus': {
                    data: servers
                }
            }
        },
        firewallRules: {
            listByServerPostgres: {
                'eastus': {}
            }
        }
    };

    if (serverId1) {
        cache.firewallRules.listByServerPostgres.eastus[serverId1] = {
            data: rules1 || []
        };
    }

    if (serverId2) {
        cache.firewallRules.listByServerPostgres.eastus[serverId2] = {
            data: rules2 || []
        };
    }

    return cache;
};

describe('postgresqlServerPublicAccess', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([]);
            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if server has public network access disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The PostgreSQL server has public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresServer[0]]);
            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if server has public access enabled but no firewall rules', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL Server Firewall Rules found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresServer[1]], []);
            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if server has public access enabled but restrictive firewall rules', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The PostgreSQL server is protected from outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresServer[1]], [firewallRules[0]]);
            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should give failing result if server has firewall rule allowing 0.0.0.0/0 access (full range)', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The PostgreSQL server is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresServer[1]], [firewallRules[1]]);
            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should give failing result if server has firewall rule allowing 0.0.0.0/0 access (0.0.0.0-0.0.0.0)', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The PostgreSQL server is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresServer[1]], [firewallRules[2]]);
            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should give failing result if server has AllowAllWindowsAzureIPs firewall rule', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The PostgreSQL server is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresServer[1]], [firewallRules[4]]);
            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if server has customer defined IP in firewall rules', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The PostgreSQL server is protected from outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresServer[1]], [firewallRules[3]]);
            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for PostgreSQL Servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for PostgreSQL servers');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = {
                servers: {
                    listPostgres: {
                        'eastus': {
                            err: 'Error querying servers'
                        }
                    }
                }
            };

            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query firewall rules', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query PostgreSQL Server Firewall Rules');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = {
                servers: {
                    listPostgres: {
                        'eastus': {
                            data: [listPostgresServer[1]]
                        }
                    }
                },
                firewallRules: {
                    listByServerPostgres: {
                        'eastus': {
                            [listPostgresServer[1].id]: {
                                err: 'Error querying firewall rules'
                            }
                        }
                    }
                }
            };

            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should check firewall rules if server has no publicNetworkAccess property', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The PostgreSQL server is protected from outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresServer[2]], [firewallRules[0]]);
            postgresqlServerPublicAccess.run(cache, {}, callback);
        });

        it('should give failing result if server has firewall rule with customer defined IP as end address', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The PostgreSQL server is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresServer[2]], [firewallRules[5]]);
            postgresqlServerPublicAccess.run(cache, {postgresql_server_allowed_ips: '10.0.0.1'}, callback);
        });

        it('should give passing result if server has firewall rule with customer defined IP but not matching allowed IPs', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The PostgreSQL server is protected from outside traffic');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([listPostgresServer[2]], [firewallRules[5]]);
            postgresqlServerPublicAccess.run(cache, {postgresql_server_allowed_ips: '192.168.1.1'}, callback);
        });
    });
});