var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./secretExpirationEnabled');

const createCache = (err, data) => {
    return {
        KeyVaultClient: {
            getSecrets: {
                'eastus': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('secretExpirationEnabled', function () {
    describe('run', function () {
        it('should give passing result if no secrets found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No secrets found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if expiration is not set on secrets', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Expiry date is not set for the secret');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "https://test1.vault.azure.net/secrets/test",
                        "attributes": {
                            "enabled": true,
                            "created": "2019-10-28T19:11:09.000Z",
                            "updated": "2019-10-28T19:19:40.000Z",
                            "recoveryLevel": "Purgeable"
                        },
                        "tags": {},
                        "location": "eastus",
                        "storageAccount": {
                            "name": "test"
                        }
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if expiration is set on keys', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Expiry date is set for the secret');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "https://test1.vault.azure.net/secrets/test",
                        "attributes": {
                            "enabled": true,
                            "expires": "2021-10-28T19:10:52.000Z",
                            "created": "2019-10-28T19:11:09.000Z",
                            "updated": "2019-10-28T19:19:40.000Z",
                            "recoveryLevel": "Purgeable"
                        },
                        "tags": {},
                        "location": "eastus",
                        "storageAccount": {
                            "name": "test"
                        }
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if key is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The secret is disabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "https://test1.vault.azure.net/secrets/test",
                        "attributes": {
                            "enabled": false,
                            "expires": "2021-10-28T19:10:52.000Z",
                            "created": "2019-10-28T19:11:09.000Z",
                            "updated": "2019-10-28T19:19:40.000Z",
                            "recoveryLevel": "Purgeable"
                        },
                        "tags": {},
                        "location": "eastus",
                        "storageAccount": {
                            "name": "test"
                        }
                    }
                ]
            );

            auth.run(cache, {}, callback);
        })
    })
});