var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./serverAuditingEnabled');

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
        serverBlobAuditingPolicies: {
            get: {
                'eastus': get
            }
        }
    }
};

describe('serverAuditingEnabled', function() {
    describe('run', function() {
        it('should give passing result if no auditing policies', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [],
                {}
            );

            auth.run(cache, {}, callback);
        })

        it('should give failing result if sql server auditing is disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Server auditing is not enabled on the SQL Server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Sql/servers/gioservertest1",
                        "name": "connection_throttling",
                        "type": "Microsoft.Sql/servers"
                    }
                ],
                {
                    '/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Sql/servers/gioservertest1': {
                        data: [
                            {
                                "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/giotestserver1/auditingSettings/Default",
                                "name": "Default",
                                "type": "Microsoft.Sql/servers/auditingSettings",
                                "state": "Disabled",
                                "storageEndpoint": "",
                                "retentionDays": 0,
                                "auditActionsAndGroups": [],
                                "storageAccountSubscriptionId": "00000000-0000-0000-0000-000000000000",
                                "isStorageSecondaryKeyInUse": false,
                                "isAzureMonitorTargetEnabled": true,
                                "error": false,
                                "location": "eastus",
                                "storageAccount": {
                                    "name": "giotestserver1"
                                }
                            }
                        ]
                    }
                }
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if enabled App Service', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Server auditing is enabled on the SQL Server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Sql/servers/gioservertest1",
                        "name": "connection_throttling",
                        "type": "Microsoft.Sql/servers"
                    }
                ],
                {
                    '/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.Sql/servers/gioservertest1': {
                        data: [
                            {
                                "id": "/subscriptions/ade0e01e-f9cd-49d3-bba7-d5a5362a3414/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/giotestserver1/auditingSettings/Default",
                                "name": "Default",
                                "type": "Microsoft.Sql/servers/auditingSettings",
                                "state": "Enabled",
                                "storageEndpoint": "",
                                "retentionDays": 0,
                                "auditActionsAndGroups": [
                                    "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
                                    "FAILED_DATABASE_AUTHENTICATION_GROUP",
                                    "BATCH_COMPLETED_GROUP"
                                ],
                                "storageAccountSubscriptionId": "00000000-0000-0000-0000-000000000000",
                                "isStorageSecondaryKeyInUse": false,
                                "isAzureMonitorTargetEnabled": true,
                                "error": false,
                                "location": "eastus",
                                "storageAccount": {
                                    "name": "giotestserver1"
                                }
                            }
                        ]
                    }
                }
            );

            auth.run(cache, {}, callback);
        });
    })
})