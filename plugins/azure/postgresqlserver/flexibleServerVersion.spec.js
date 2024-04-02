var expect = require('chai').expect;
var flexibleServerVersion = require('./flexibleServerVersion');

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
        "version": '13'
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server1",
        "type": "Microsoft.DBforPostgreSQL/flexibleServers",
        "storageProfile": {
            "storageMB": 5120,
            "backupRetentionDays": 7,
            "geoRedundantBackup": "Disabled",
            "storageAutogrow": "Disabled"
        },
        "version": '10'
    }
];


const createCache = (list) => {
    return {
        servers: {
            listPostgresFlexibleServer: {
                'eastus': {
                    data: list
                }
            }
        }
    }
};

describe('flexibleServerVersion', function() {
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

            flexibleServerVersion.run(cache, {}, callback);
        })

        it('should give failing result if postgresql flexiable server does nothave the latest version', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('PostgreSQL flexible server does not the latest server version');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listPostgresFlexibleServer[1]]
            );

            flexibleServerVersion.run(cache, {}, callback);
        });

        it('should give passing result if postgresql server have the latest version', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('PostgreSQL flexible server has the latest server version');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listPostgresFlexibleServer[0]]
            );

            flexibleServerVersion.run(cache, {}, callback);
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

            flexibleServerVersion.run(cache, {}, callback);
        });
    })
})
