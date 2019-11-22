var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./serviceAccountKeyRotation');

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

describe('serviceAccountKeyRotation', function () {
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

        it('should give passing result if the projects services are all within service limits', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('he service account key has been rotated within 90 days');
                expect(results[0].region).to.equal('global');
                done()
            };
            var firstDay = new Date();
            var eighty_days_ago = new Date(firstDay.getTime() - 80 * 24 * 60 * 60 * 1000);
            eighty_days_ago = eighty_days_ago.toISOString();

            const cache = createCache(
                null,
                [
                    {
                        "name": "projects/example-project/serviceAccounts/test@example-project.iam.gserviceaccount.com/keys/1234564354235fg34523562536",
                        "validAfterTime": eighty_days_ago,
                        "validBeforeTime": "2019-11-17T18:56:00Z",
                        "keyAlgorithm": "KEY_ALG_RSA_2048",
                        "keyOrigin": "GOOGLE_PROVIDED",
                        "keyType": "USER_MANAGED"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if the projects services are very close to the service limits', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The service account key has not been rotated in over 90 days');
                expect(results[0].region).to.equal('global');
                done()
            };

            var firstDay = new Date();
            var ninety_days_ago = new Date(firstDay.getTime() - 90 * 25 * 60 * 60 * 1000);
            ninety_days_ago = ninety_days_ago.toISOString();

            const cache = createCache(
                null,
                [
                    {
                        "name": "projects/example-project/serviceAccounts/test@example-project.iam.gserviceaccount.com/keys/1234564354235fg34523562536",
                        "validAfterTime": ninety_days_ago,
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