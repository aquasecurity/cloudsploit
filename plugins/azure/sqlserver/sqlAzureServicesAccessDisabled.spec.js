var expect = require('chai').expect;
var sqlServerServicesAccessDisabled = require('./sqlAzureServicesAccessDisabled');

const listSql = [
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/test-rg/providers/Microsoft.Sql/servers/sql-server-1",
        "name": "sql-server-1",
        "type": "Microsoft.Sql/servers",
        "location": "East US",
        "publicNetworkAccess": "Enabled"
    },
];

const firewallRules = [
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/test-rg/providers/Microsoft.Sql/servers/sql-server-1/firewallRules/TestRule",
        "name": "testRule",
        "type": "Microsoft.Sql/servers/firewallRules",
        "location": "East US",
        "kind": "v12.0",
    },
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/test-rg/providers/Microsoft.Sql/servers/sql-server-1/firewallRules/AllowAllWindowsAzureIps",
        "name": "AllowAllWindowsAzureIps",
        "type": "Microsoft.Sql/servers/firewallRules",
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
            listSql: {
                'eastus': {
                    data: list
                }
            }
        },
        firewallRules: {
            listByServer: {
                'eastus': {
                    [serverId]: {
                        data: rules
                    }
                }
            }
        }
    };
};

describe('sqlServerServicesAccessDisabled', function () {
    describe('run', function () {
        it('should give passing result if no SQL servers', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache([]);

            sqlServerServicesAccessDisabled.run(cache, {}, callback);
        });

        it('should give failing result if SQL server does not have access disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Access to other Azure services is not disabled for SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [listSql[0]],
                [firewallRules[1]]
            );

            sqlServerServicesAccessDisabled.run(cache, {}, callback);
        });

        it('should give passing result if SQL server not have access to azure services', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Access to other Azure services is disabled for SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [listSql[0]],
                [firewallRules[0]]
            );

            sqlServerServicesAccessDisabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL Servers', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                null
            );

            sqlServerServicesAccessDisabled.run(cache, {}, callback);
        });
    });
});
