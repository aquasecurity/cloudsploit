var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./sendAlertsEnabled');

const createCache = (err, data) => {
    return {
        serverSecurityAlertPolicies: {
            listByServer: {
                'eastus': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('sendAlertsEnabled', function () {
    describe('run', function () {
        it('should give passing result if no Database Threat Detection policies', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Database Threat Detection policies found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        })

        it('should give failing result if send alerts is not configured', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Send alerts is not enabled on the sql server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/aee7c96a-d866-4cdb-b13b-4050e4849fb9/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/testserver1/securityAlertPolicies/Default",
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
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if enabled App Service', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Send alerts is enabled on the sql server');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
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
            );

            auth.run(cache, {}, callback);
        });
    })
})