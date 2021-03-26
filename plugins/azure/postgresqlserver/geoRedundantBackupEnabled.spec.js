var assert = require('assert');
var expect = require('chai').expect;
var geoRedundantBackupEnabled = require('./geoRedundantBackupEnabled');

const listPostgres = [
    {
        "id": "/subscriptions/jk34n234k-dwef/resourceGroups/akhtar-rg/providers/Microsoft.DBforPostgreSQL/servers/geo-redundant",
        "type": "Microsoft.DBforPostgreSQL/servers",
        "storageProfile": {
            "storageMB": 5120,
            "backupRetentionDays": 7,
            "geoRedundantBackup": "Disabled",
            "storageAutogrow": "Disabled"
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

describe('geoRedundantBackupEnabled', function() {
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

            geoRedundantBackupEnabled.run(cache, {}, callback);
        })

        it('should give failing result if postgresql server has geo-redundant backup storage enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('PostgreSQL Server does not have geo-redundant backup storage enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [listPostgres[0]]
            );

            geoRedundantBackupEnabled.run(cache, {}, callback);
        });

        it('should give passing result if postgresql server does not have geo-redundant backup storage enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('PostgreSQL Server has geo-redundant backup storage enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [listPostgres[1]]
            );

            geoRedundantBackupEnabled.run(cache, {}, callback);
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

            geoRedundantBackupEnabled.run(cache, {}, callback);
        });
    })
})