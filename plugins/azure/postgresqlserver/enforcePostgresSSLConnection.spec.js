var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./enforcePostgresSSLConnection');

const createCache = (err, data) => {
    return {
        servers: {
            listPostgres: {
                'eastus': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('enforcePostgresSSLConnection', function() {
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

            auth.run(cache, {}, callback);
        })

        it('should give failing result if postgresql server has SSL enforcement disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The PostgreSQL Server is not configured to enforce SSL connections');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.DBforPostgreSQL/servers/gioservertest1",
                        "name": "gioservertest1",
                        "type": "Microsoft.DBforPostgreSQL/servers",
                        "location": "ukwest",
                        "tags": {
                            "environment": "dev"
                        },
                        "sku": {
                            "name": "B_Gen5_1",
                            "tier": "Basic",
                            "capacity": 1,
                            "family": "Gen5"
                        },
                        "administratorLogin": "gio",
                        "version": "10",
                        "sslEnforcement": "Disabled",
                        "userVisibleState": "Ready",
                        "fullyQualifiedDomainName": "gioservertest1.postgres.database.azure.com",
                        "earliestRestoreDate": "2019-10-10T21:32:39.610Z",
                        "storageProfile": {
                            "backupRetentionDays": 7,
                            "geoRedundantBackup": "Disabled",
                            "storageMB": 5120
                        },
                        "replicationRole": "",
                        "masterServerId": ""
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if postgresql server has SSL enforcement enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The PostgreSQL Server is configured to enforce SSL connections');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.DBforPostgreSQL/servers/gioservertest1",
                        "name": "gioservertest1",
                        "type": "Microsoft.DBforPostgreSQL/servers",
                        "location": "ukwest",
                        "tags": {
                            "environment": "dev"
                        },
                        "sku": {
                            "name": "B_Gen5_1",
                            "tier": "Basic",
                            "capacity": 1,
                            "family": "Gen5"
                        },
                        "administratorLogin": "gio",
                        "version": "10",
                        "sslEnforcement": "Enabled",
                        "userVisibleState": "Ready",
                        "fullyQualifiedDomainName": "gioservertest1.postgres.database.azure.com",
                        "earliestRestoreDate": "2019-10-10T21:32:39.610Z",
                        "storageProfile": {
                            "backupRetentionDays": 7,
                            "geoRedundantBackup": "Disabled",
                            "storageMB": 5120
                        },
                        "replicationRole": "",
                        "masterServerId": ""
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });
    })
})