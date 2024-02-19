var expect = require('chai').expect;
var sqlServerVNetIntegrated = require('./sqlServerVNetRuleIntegrated');

const listSqlServers = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.Sql/servers/test-sql-server",
        "type": "Microsoft.Sql/servers",
        "storageProfile": {
            "backupRetentionDays": 7,
            "geoRedundantBackup": "Disabled",
            "storageAutogrow": "Disabled"
        },
        "publicNetworkAccess": "Enabled"
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.Sql/servers/test-sql-server2",
        "type": "Microsoft.Sql/servers",
        "storageProfile": {
            "backupRetentionDays": 7,
            "geoRedundantBackup": "Disabled",
            "storageAutogrow": "Disabled"
        },
        "publicNetworkAccess": "Disabled"
    }
];

const virtualNetworkRules = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.Sql/servers/test-sql-server/virtualNetworkRules/TestRule",
        "name": "TestRule",
        "type": "Microsoft.Sql/servers/virtualNetworkRules",
        "location": "East US",
        "properties": {
            "virtualNetworkSubnetId": "/subscriptions/12345/resourceGroups/cloudsploit-dev/providers/Microsoft.Network/virtualNetworks/test/subnets/default"
        }
    }
];

const createCache = (listSqlServers, rules) => {
    const serverId = (listSqlServers && listSqlServers.length) ? listSqlServers[0].id : null;
    return {
        servers: {
            listSql: {
                'eastus': {
                    data: listSqlServers
                }
            }
        },
        virtualNetworkRules: {
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

describe('sqlServerVNetIntegrated', function () {
    describe('run', function () {
        it('should give passing result if no servers', function (done) {
            const cache = createCache([]);
            sqlServerVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if VNet is not configured', function (done) {
            const cache = createCache([listSqlServers[0]],[]);
            sqlServerVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL server does not have VNet rule integrated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if VNet is configured', function (done) {
            const cache = createCache([listSqlServers[1]], [virtualNetworkRules[0]]);
            sqlServerVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL server has VNet rule integrated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query SQL Servers', function (done) {
            const cache = createCache(null);
            sqlServerVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
