var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./authEnabled');

const createCache = (err, list, data) => {
    return {
        webApps: {
            list: {
                'eastus': {
                    data: list
                }
            },
            getAuthSettings: {
                'eastus': data
            }
        }
    }
};

describe('authEnabled', function() {
    describe('run', function() {
        it('should give passing result if no App Services', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No existing App Service')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [],
                {}
            );

            auth.run(cache, {}, callback);
        })

        it('should give failing result if disable App Service', function(done) {
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
                        "id": "/subscriptions/abcdef-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/devresourcegroup/providers/Microsoft.Web/sites/test-webapp",
                        "name": "gio-test-webapp",
                        "type": "Microsoft.Web/sites",
                        "kind": "app,linux,container",
                        "location": "East US",
                        "state": "Running"
                    }
                ],
                {
                    "/subscriptions/abcdef-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/devresourcegroup/providers/Microsoft.Web/sites/test-webapp": {
                        "data": {
                            "name": "authsettings",
                            "type": "Microsoft.Web/sites/config",
                            "enabled": false
                        }
                    }
                }
            );

            auth.run(cache, {}, callback);
        })

        it('should give passing result if enabled App Service', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('App Service has App Service Authentication enabled')
                expect(results[0].region).to.equal('eastus')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/abcdef-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/devresourcegroup/providers/Microsoft.Web/sites/test-webapp",
                        "name": "gio-test-webapp",
                        "type": "Microsoft.Web/sites",
                        "kind": "app,linux,container",
                        "location": "East US",
                        "state": "Running"
                    }
                ],
                {
                    "/subscriptions/abcdef-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/devresourcegroup/providers/Microsoft.Web/sites/test-webapp": {
                        "data": {
                            "name": "authsettings",
                            "type": "Microsoft.Web/sites/config",
                            "enabled": true
                        }
                    }
                }
            );

            auth.run(cache, {}, callback);
        })
    })
})