// Import necessary modules and the code to be tested
var assert = require('assert');
var expect = require('chai').expect;
var auditSupportOperations = require('./auditOperationsEnabled');

// Function to create a sample cache
const createCache = (err, list, get) => {
    return {
        servers: {
            listSql: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        },
        devOpsAuditingSettings: {
            list: {
                'eastus': get
            }
        }
    }
};

// Test suite
describe('Auditing of Microsoft Support Operations', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                null,
                [],
                {}
            );

            auditSupportOperations.run(cache, {}, callback);
        });

        it('should give passing result if auditing of support operations is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Microsoft support operations auditing is enabled on SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/subscription-id/resourceGroups/resource-group/providers/Microsoft.Sql/servers/sql-server",
                        "name": "sql-server",
                        "type": "Microsoft.Sql/servers"
                    }
                ],
                {
                    '/subscriptions/subscription-id/resourceGroups/resource-group/providers/Microsoft.Sql/servers/sql-server': {
                        data: [
                            {
                                "id": "/subscriptions/subscription-id/resourceGroups/resource-group/providers/Microsoft.Sql/servers/sql-server/auditingSettings/Default",
                                "name": "Default",
                                "type": "Microsoft.Sql/servers/auditingSettings",
                                "state": "Enabled",
                                "error": false,
                                "location": "eastus"
                            }
                        ]
                    }
                }
            );

            auditSupportOperations.run(cache, {}, callback);
        });

        it('should give failing result if auditing of support operations is not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Microsoft support operations auditing is not enabled on SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/subscription-id/resourceGroups/resource-group/providers/Microsoft.Sql/servers/sql-server",
                        "name": "sql-server",
                        "type": "Microsoft.Sql/servers"
                    }
                ],
                {
                    '/subscriptions/subscription-id/resourceGroups/resource-group/providers/Microsoft.Sql/servers/sql-server': {
                        data: [
                            {
                                "id": "/subscriptions/subscription-id/resourceGroups/resource-group/providers/Microsoft.Sql/servers/sql-server/auditingSettings/Default",
                                "name": "Default",
                                "type": "Microsoft.Sql/servers/auditingSettings",
                                "state": "Disabled",
                                "error": false,
                                "location": "eastus"
                            }
                        ]
                    }
                }
            );

            auditSupportOperations.run(cache, {}, callback);
        });
    });
});
