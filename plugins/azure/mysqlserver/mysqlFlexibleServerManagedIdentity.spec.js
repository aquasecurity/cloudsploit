var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./mysqlFlexibleServerManagedIdentity');

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

describe('mysqlFlexibleServerManagedIdentity', function() {
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

        it('should FAIL if MySQL server does not have managed identity', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('MySQL flexible server does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server",
                        "type": "Microsoft.DBforMySQL/flexibleServers",
                        "version": '5.8'
                    }
                ],
            );

            auth.run(cache, {}, callback);
        });

        it('should PASS if MySQL server is using latest version', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('MySQL flexible server has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server",
                        "type": "Microsoft.DBforMySQL/flexibleServers",
                        "version": "8.0",
                        "identity": {
                            "type": "userassigned"
                        }
                    }
                ]
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
        });
    })
})