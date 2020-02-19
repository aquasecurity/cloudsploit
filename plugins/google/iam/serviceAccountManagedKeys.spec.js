var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./serviceAccountManagedKeys');

const createCache = (err, data) => {
    return {
        keys: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('serviceAccountManagedKeys', function () {
    describe('run', function () {
        it('should give unknown result if a project error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query service account keys');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no project records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No service account keys found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if the service account keys are being managed by google', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The user service account key is being managed by Google');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "projects/example-project/serviceAccounts/test@example-project.iam.gserviceaccount.com/keys/1234564354235fg34523562536",
                        "validAfterTime": "2019-11-17T18:56:00Z",
                        "validBeforeTime": "2019-11-17T18:56:00Z",
                        "keyAlgorithm": "KEY_ALG_RSA_2048",
                        "keyOrigin": "GOOGLE_PROVIDED",
                        "keyType": "SYSTEM_MANAGED"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if the service account keys are not being managed by google', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The user service account key is not being managed by Google');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "projects/example-project/serviceAccounts/test@example-project.iam.gserviceaccount.com/keys/1234564354235fg34523562536",
                        "validAfterTime": "2019-11-17T18:56:00Z",
                        "validBeforeTime": "2019-11-17T18:56:00Z",
                        "keyAlgorithm": "KEY_ALG_RSA_2048",
                        "keyOrigin": "GOOGLE_PROVIDED",
                        "keyType": "USER_MANAGED"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
});