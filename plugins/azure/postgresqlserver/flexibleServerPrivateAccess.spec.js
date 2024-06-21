var expect = require('chai').expect;
var flexibleServerPrivateAccess = require('./flexibleServerPrivateAccess');

const listPostgresFlexibleServer = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server",
        "type": "Microsoft.DBforPostgreSQL/flexibleServers",
        "storageProfile": {
            "storageMB": 5120,
            "backupRetentionDays": 7,
            "geoRedundantBackup": "Disabled",
            "storageAutogrow": "Disabled"
        },
    }
];

const firewallRules = [
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/akhtar-rg/providers/Microsoft.DBforPostgreSQL/servers/geo-redundant/firewallRules/TestRule",
        "name": "testRule",
        "type": "Microsoft.DBforPostgreSQL/servers/firewallRules",
        "location": "East US",
        "kind": "v12.0",
    },
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/akhtar-rg/providers/Microsoft.DBforPostgreSQL/servers/geo-redundant/firewallRules/AllowAllWindowsAzureIps",
        "name": "AllowAllAzureServicesAndResourcesWithinAzureIps_2023-12-1_16-2-47')",
        "type": "Microsoft.DBforPostgreSQL/servers/firewallRules",
        "location": "East US",
        "kind": "v12.0",
        "properties": {
            "startIpAddress": "0.0.0.0",
            "endIpAddress": "0.0.0.0"
      },
    },
];
const createCache = (list, rules) => {
    const serverId = (list && list.length) ? list[0].id : null;
    return {
        servers: {
            listPostgresFlexibleServer: {
                'eastus': {
                    data: list
                }
            }
        },
        firewallRules: {
            listByFlexibleServerPostgres: {
                'eastus': {
                    [serverId]: {
                        data: rules
                    }
                }
            }
        }
    }
};

describe('flexibleServerPrivateAccess', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL flexible servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([]);

            flexibleServerPrivateAccess.run(cache, {}, callback);
        })

        it('should give failing result if postgresql flexiable server does not have access disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Access to other Azure services is not disabled for PostgreSQL flexible server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listPostgresFlexibleServer[0]],
                [firewallRules[1]]
            );

            flexibleServerPrivateAccess.run(cache, {}, callback);
        });

        it('should give passing result if postgresql server not have access to azure services', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Access to other Azure services is disabled for PostgreSQL flexible server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listPostgresFlexibleServer[0]],
                [firewallRules[0]]
            );

            flexibleServerPrivateAccess.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for PostgreSQL Servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for PostgreSQL flexible servers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null
            );

            flexibleServerPrivateAccess.run(cache, {}, callback);
        });
    })
})