var expect = require('chai').expect;
var azureServicesAccessDisabled = require('./azureServicesAccessDisabled');

const listPostgres = [
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/akhtar-rg/providers/Microsoft.DBforPostgreSQL/servers/geo-redundant",
        "type": "Microsoft.DBforPostgreSQL/servers",
        "storageProfile": {
            "storageMB": 5120,
            "backupRetentionDays": 7,
            "geoRedundantBackup": "Disabled",
            "storageAutogrow": "Disabled"
        },
        "properties": {
            "publicNetworkAccess": "Enabled"
        }
    },
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/akhtar-rg/providers/Microsoft.DBforPostgreSQL/servers/geo-redundant",
        "type": "Microsoft.DBforPostgreSQL/servers",
        "storageProfile": {
            "storageMB": 5120,
            "backupRetentionDays": 7,
            "geoRedundantBackup": "Enabled",
            "storageAutogrow": "Disabled"
        },
        "properties": {
            "publicNetworkAccess": "Disabled"
        }
    }
];
const createCache = (err, list) => {
    return {
        servers: {
            listPostgres: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        }
    }
};

describe('azureServicesAccessDisabled', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL Servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            azureServicesAccessDisabled.run(cache, {}, callback);
        })

        it('should give failing result if postgresql server does not have public network access disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The PostgreSQL Server does not have public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [listPostgres[0]]
            );

            azureServicesAccessDisabled.run(cache, {}, callback);
        });

        it('should give passing result if postgresql server public network access disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The PostgreSQL Server has public network access disabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [listPostgres[1]]
            );

            azureServicesAccessDisabled.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for PostgreSQL Servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for PostgreSQL Servers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                { message: "Unable to list servers" },
            );

            azureServicesAccessDisabled.run(cache, {}, callback);
        });
    })
})