var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./emailAccountAdminsEnabled');

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
        serverSecurityAlertPolicies: {
            listByServer: {
                'eastus': get
            }
        }
    }
};

describe('emailAccountAdminsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no Database Threat Detection policies', function(done) {
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

        it('should give failing result if email account admins is not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Email Account Admins is not enabled on the SQL server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/giotestserver1",
                        "name": "giotestserver1",
                        "type": "Microsoft.Sql/servers",
                        "location": "eastus"
                    }
                ],
                {
                    '/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/giotestserver1': {
                        data: [
                            {
                                "id": "/subscriptions/aee7c96a-d866-4cdb-b13b-4050e4849fb9/resourceGroups/testresourcegroup/providers/Microsoft.Sql/servers/testserver1/securityAlertPolicies/Default",
                                "name": "Default",
                                "type": "Microsoft.Sql/servers/securityAlertPolicies",
                                "state": "Enabled",
                                "disabledAlerts": [
                                    "Sql_Injection"
                                ],
                                "emailAddresses": [
                                    ""
                                ],
                                "emailAccountAdmins": false,
                                "storageEndpoint": "",
                                "storageAccountAccessKey": "",
                                "retentionDays": 0,
                                "creationTime": "2019-10-16T00:10:41.983Z",
                                "location": "eastus",
                                "storageAccount": {
                                    "name": "testserver1"
                                }
                            }
                        ]
                    }
                }
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if email account admins is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Email Account Admins is enabled on the SQL server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/giotestserver1",
                        "name": "giotestserver1",
                        "type": "Microsoft.Sql/servers",
                        "location": "eastus"
                    }
                ],
                {
                    '/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/giotestserver1': {
                        data: [
                            {
                                "id": "/subscriptions/aee7c96a-d866-4cdb-b13b-4050e4849fb9/resourceGroups/testresourcegroup/providers/Microsoft.Sql/servers/testserver1/securityAlertPolicies/Default",
                                "name": "Default",
                                "type": "Microsoft.Sql/servers/securityAlertPolicies",
                                "state": "Enabled",
                                "disabledAlerts": [
                                    "Sql_Injection"
                                ],
                                "emailAddresses": [
                                    "John@carroll.com"
                                ],
                                "emailAccountAdmins": true,
                                "storageEndpoint": "",
                                "storageAccountAccessKey": "",
                                "retentionDays": 0,
                                "creationTime": "2019-10-16T00:10:41.983Z",
                                "location": "eastus",
                                "storageAccount": {
                                    "name": "testserver1"
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