var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./postgresqlInfraDoubleEncryption');

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

describe('postgresqlInfraDoubleEncryption', function() {
    describe('run', function() {
        it('should PASS if no servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        })

        it('should FAIL if postgresql server has Infrastructure Double Encryption disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Infrastructure double encryption is not enabled for PostgreSQL server');
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
                        "infrastructureEncryption": 'Disabled',
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should PASS if postgresql server has Infrastructure Double Encryption enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Infrastructure double encryption is enabled for PostgreSQL server');
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
                        "infrastructureEncryption": 'Enabled',
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        
    })
})