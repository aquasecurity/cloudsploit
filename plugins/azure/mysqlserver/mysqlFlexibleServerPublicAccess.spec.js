var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./mysqlFlexibleServerPublicAccess');

const createCache = (err, list) => {
    return {
        servers: {
            listMysqlFlexibleServer: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        }
    }
};

describe('mysqlFlexibleServerPublicAccess', function() {
    describe('run', function() {
        it('should PASS if no existing servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing MySQL flexible servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [],
                {}
            );

            auth.run(cache, {}, callback);
        });

        it('should FAIL if MySQL server is not publicly accessible', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('MySQL flexible server is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server",
                        "type": "Microsoft.DBforMySQL/flexibleServers",
                        "properties": {
                            "administratorLogin": "test",
                            "storage": {
                                "storageSizeGB": 20,
                                "iops": 360,
                                "autoGrow": "Enabled",
                                "autoIoScaling": "Enabled",
                                "storageSku": "Premium_LRS",
                                "logOnDisk": "Disabled"
                            },
                            "version": "5.7",
                            "state": "Ready",
                            "fullyQualifiedDomainName": "test-flexibleserverr-mysql.mysql.database.azure.com",
                            "availabilityZone": "3",
                            "replicationRole": "None",
                            "replicaCapacity": 10,
                        },
                        "network": {
                            "publicNetworkAccess": "Disabled"
                        },
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should FAIL if MySQL server is publicly accessible', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('MySQL flexible server is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server",
                        "type": "Microsoft.DBforMySQL/flexibleServers",
                        "properties": {
                            "administratorLogin": "test",
                            "storage": {
                                "storageSizeGB": 20,
                                "iops": 360,
                                "autoGrow": "Enabled",
                                "autoIoScaling": "Enabled",
                                "storageSku": "Premium_LRS",
                                "logOnDisk": "Disabled"
                            },
                            "version": "5.7",
                            "state": "Ready",
                            "fullyQualifiedDomainName": "test-flexibleserverr-mysql.mysql.database.azure.com",
                            "availabilityZone": "3",
                            "replicationRole": "None",
                            "replicaCapacity": 10,
                        },
                        "network": {
                            "publicNetworkAccess": "Enabled"
                        },
                    }
                ],
            );

            auth.run(cache, {}, callback);
        });

        it('should UNKNOWN if unable to query for server', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for MySQL flexible servers: ');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null, null
            );

            auth.run(cache, {}, callback);
        })
    })
})