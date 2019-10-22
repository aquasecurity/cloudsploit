var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./authEnabled');

const createCache = (err, data) => {
    return {
        webApps: {
            getAuthSettings: {
                'eastus': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('authEnabled', function () {
    describe('run', function () {
        it('should give passing result if no App Services', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No existing App Service')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        })

        it('should give failing result if disable App Service', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('App Service does not have App Service Authentication enabled')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/example/resourceGroups/devresourcegroup/providers/Microsoft.Web/sites/sample/config/authsettings",
                        "name": "authsettings",
                        "type": "Microsoft.Web/sites/config",
                        "enabled": false,
                        "runtimeVersion": "1.0.0",
                        "unauthenticatedClientAction": "AllowAnonymous",
                        "tokenStoreEnabled": true,
                        "defaultProvider": "AzureActiveDirectory",
                        "error": false,
                        "location": "eastus",
                        "storageAccount": {
                            "name": "cloudsploit"
                        }
                      }
                ]
            );

            auth.run(cache, {}, callback);
        })

        it('should give passing result if enabled App Service', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('All App Services have App Service Authentication enabled')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/example/resourceGroups/devresourcegroup/providers/Microsoft.Web/sites/sample/config/authsettings",
                        "name": "authsettings",
                        "type": "Microsoft.Web/sites/config",
                        "enabled": true,
                        "runtimeVersion": "1.0.0",
                        "unauthenticatedClientAction": "AllowAnonymous",
                        "tokenStoreEnabled": true,
                        "defaultProvider": "AzureActiveDirectory",
                        "error": false,
                        "location": "eastus",
                        "storageAccount": {
                            "name": "cloudsploit"
                        }
                      }
                ]
            );

            auth.run(cache, {}, callback);
        })
    })
})