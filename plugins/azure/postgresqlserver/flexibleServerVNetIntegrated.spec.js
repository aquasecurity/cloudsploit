var expect = require('chai').expect;
var flexibleServerVNetIntegrated = require('./flexibleServerVNetIntegrated');

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
    "network":{
        "publicNetworkAccess": "Enabled"
    }
},
{
    "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server2",
    "type": "Microsoft.DBforPostgreSQL/flexibleServers",
    "storageProfile": {
        "storageMB": 5120,
        "backupRetentionDays": 7,
        "geoRedundantBackup": "Disabled",
        "storageAutogrow": "Disabled"
    },
    "network":{
        "delegatedSubnetResourceId" : "/subscriptions/12345/resourceGroups/cloudsploit-dev/providers/Microsoft.Network/virtualNetworks/test/subnets/default",
        "privateDnsZoneArmResourceId" : "/subscriptions/12345/resourceGroups/cloudsploit-dev/providers/Microsoft.Network/privateDnsZones/testflexibleserver11.private.postgres.database.azure.com",
        "publicNetworkAccess": "Disabled"
    }
    
}
   
];

const createCache = (listPostgres) => {
    return {
        servers: {
            listPostgresFlexibleServer: {
                'eastus': {
                    data: listPostgres
                }
            }
        }
    };
};

describe('flexibleServerVNetIntegrated', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const cache = createCache({});
            flexibleServerVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL flexible servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Vnet is not configured', function(done) {
            const cache = createCache([listPostgresFlexibleServer[0]]);
            flexibleServerVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('PostgreSQL flexible server does not have VNet integrated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give should give passing result if Vnet is configured', function(done) {
            const cache = createCache([listPostgresFlexibleServer[1]]);
            flexibleServerVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('PostgreSQL flexible server has VNet integrated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give UnKnown result if unable to query postgreSQL Server', function(done) {
            const cache = createCache(null);
            flexibleServerVNetIntegrated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for PostgreSQL flexible servers: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        
    })
})
