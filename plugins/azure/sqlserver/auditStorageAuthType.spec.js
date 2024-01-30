var assert = require('assert');
var expect = require('chai').expect;
var auditLogsAuthentication = require('./auditStorageAuthType');

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

describe('Storage Authentication Type for Audit Logs', function() {
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

            auditLogsAuthentication.run(cache, {}, callback);
        });

        it('should give passing result if Azure SQL Auditing is not using account storage', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Server is not using a storage account as destination for audit logs');
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
                                "storageEndpoint": "",
                                "retentionDays": 0,
                                "auditActionsAndGroups": [],
                                "storageAccountSubscriptionId": "00000000-0000-0000-0000-000000000000",
                                "isManagedIdentityInUse": false,
                                "isAzureMonitorTargetEnabled": true,
                                "error": false,
                                "location": "eastus",
                                "storageAccount": {
                                    "name": "sqlserverstorage"
                                }
                            }
                        ]
                    }
                }
            );

            auditLogsAuthentication.run(cache, {}, callback);
        });

        it('should give passing result if managed identity is configured for audit logs storage', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Server is using managed identity authentication for storage account audit logs');
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
                                "storageEndpoint": "",
                                "retentionDays": 0,
                                "auditActionsAndGroups": [],
                                "storageAccountSubscriptionId": "storage-account-subscription-id",
                                "isManagedIdentityInUse": true,
                                "isAzureMonitorTargetEnabled": true,
                                "error": false,
                                "location": "eastus",
                                "storageAccount": {
                                    "name": "sqlserverstorage"
                                }
                            }
                        ]
                    }
                }
            );

            auditLogsAuthentication.run(cache, {}, callback);
        });

        it('should give failing result if managed identity is not configured for audit logs storage', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL Server is not using managed identity authentication for storage account audit logs');
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
                                "storageEndpoint": "",
                                "retentionDays": 0,
                                "auditActionsAndGroups": [],
                                "storageAccountSubscriptionId": "storage-account-subscription-id",
                                "isManagedIdentityInUse": false,
                                "isAzureMonitorTargetEnabled": true,
                                "error": false,
                                "location": "eastus",
                                "storageAccount": {
                                    "name": "sqlserverstorage"
                                }
                            }
                        ]
                    }
                }
            );

            auditLogsAuthentication.run(cache, {}, callback);
        });
    });
});
