var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./azureADAdminEnabled');

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
        serverAzureADAdministrators: {
            listByServer: {
                'eastus': get
            }
        }
    }
};

describe('azureADAdminEnabled', function() {
    describe('run', function() {
        it('should give passing result if no sql servers', function(done) {
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
        });

        it('should give failing result if disable App Service', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Active Directory admin is not enabled on the server');
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
                        data: {}
                    }
                }
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if enabled App Service', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Active Directory admin is enabled on the SQL server');
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
                                "id": "/subscriptions/e79d9a03-3ab3-4481-bdcd-c5db1d55420a/resourceGroups/devresourcegroup/providers/Microsoft.Sql/servers/giotestserver1/administrators/ActiveDirectory",
                                "name": "ActiveDirectory",
                                "type": "Microsoft.Sql/servers/administrators",
                                "administratorType": "ActiveDirectory",
                                "login": "giovanni@cloudsploit.com",
                                "sid": "3fc56a96-2173-49c5-b915-08886e7fafa3",
                                "tenantId": "2d4f0836-5935-47f5-954c-14e713119ac2",
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
        })
    })
})