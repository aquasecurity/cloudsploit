var expect = require('chai').expect;
var mysqlFlexibleServerPublicAccess = require('./mysqlFlexibleServerPublicAccess');

const listMysqlFlexibleServer = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server",
        "type": "Microsoft.DBforMySQL/flexibleServers",
        "network": {
            "publicNetworkAccess": "Disabled"
        }
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server-2",
        "type": "Microsoft.DBforMySQL/flexibleServers",
        "network": {
            "publicNetworkAccess": "Enabled"
        }
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server-3",
        "type": "Microsoft.DBforMySQL/flexibleServers",
        "network": {
            "publicNetworkAccess": "Disabled"
        }
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server-4",
        "type": "Microsoft.DBforMySQL/flexibleServers"
    }
];

const firewallRules = [
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.DBforMySQL/flexibleServers/test-server/firewallRules/AllowAll",
        "name": "AllowAll",
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.DBforMySQL/flexibleServers/test-server/firewallRules/AllowAllAlt",
        "name": "AllowAllAlt",
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "0.0.0.0"
    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/Microsoft.DBforMySQL/flexibleServers/test-server/firewallRules/AllowedIP",
        "name": "AllowedIP",
        "startIpAddress": "192.168.1.1",
        "endIpAddress": "192.168.1.1"
    }
];

const createCache = (servers, rules, serversErr, rulesErr) => {
    const cache = {
        servers: {
            listMysqlFlexibleServer: {
                'eastus': {
                    data: servers || [],
                    err: serversErr || null
                }
            }
        },
        firewallRules: {
            listByFlexibleServerMysql: {
                'eastus': {}
            }
        }
    };

    if (servers && servers.length > 0) {
        servers.forEach(server => {
            if (server && server.id) {
                cache.firewallRules.listByFlexibleServerMysql.eastus[server.id] = {
                    data: rules || [],
                    err: rulesErr || null
                };
            }
        });
    }

    return cache;
};

describe('mysqlFlexibleServerPublicAccess', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing MySQL flexible servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            mysqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if no existing SQL Flexible Server Firewall Rules found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing MySQL Flexible Server Firewall Rules found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listMysqlFlexibleServer[1]],
                []

            );

            mysqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });
        
        it('should give passing result if SQL Server has private network access disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('MySQL Flexible Server is protected from outside traffic');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listMysqlFlexibleServer[0]],
                []
            );

            mysqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give failing result if SQL Server is open to outside traffic', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The MySQL flexible server is open to outside traffic');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listMysqlFlexibleServer[1]],
                [firewallRules[0]]
            );

            mysqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if SQL Server firewall does not allow public access', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The MySQL flexible server is protected from outside traffic');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listMysqlFlexibleServer[1]],
                [firewallRules[2]]
            );

            mysqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give passing result if The SQL server is protected from outside traffic', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The MySQL flexible server is protected from outside traffic');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listMysqlFlexibleServer[1]],
                [firewallRules[2]]
            );

            mysqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for MySQL flexible servers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [],
                { message: 'unable to query servers'}

            );

            mysqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });

        it('should give unknown result if Unable to query for server firewall rules', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query MySQL Flexible Server Firewall Rules');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listMysqlFlexibleServer[1]],
                [],
                null,
                { message: 'Unable to query for server firewall rules'}
            );

            mysqlFlexibleServerPublicAccess.run(cache, {}, callback);
        });
    })
})