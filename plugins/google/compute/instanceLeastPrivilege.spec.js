var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instanceLeastPrivilege');

const createCache = (instanceData, instanceDatab, error) => {
    return {
        instances: {
            compute: {
                list: {
                    'us-central1-a': {
                        data: instanceData,
                        err: error
                    },
                    'us-central1-b': {
                        data: instanceDatab,
                        err: error
                    },
                    'us-central1-c': {
                        data: instanceDatab,
                        err: error
                    },
                    'us-central1-f': {
                        data: instanceDatab,
                        err: error
                    }
                }
            }
        }
    }
}

describe('instanceLeastPrivilege', function () {
    describe('run', function () {
        it('should return unknown if an instance error or no data returned', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(3);
                expect(results[4].message).to.equal('Unable to query instances');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                null,
                ['hellooo']
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass no VM Instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(0);
                expect(results[4].message).to.include('No instances found');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail with full access service account', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(2);
                expect(results[4].message).to.include('The following service accounts have full access');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        name: 'instance-1',
                        description: '',
                        zone:
                            'https://www.googleapis.com/compute/v1/projects/lofty-advantage-242315/zones/us-central1-a',
                        serviceAccounts: [
                            {
                                email: '413092707322-compute@developer.gserviceaccount.com',
                                scopes: [
                                    'https://www.googleapis.com/auth/cloud-platform'
                                ]
                            }
                        ]
                    }
                ],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass with no full access service account', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(0);
                expect(results[4].message).to.include('All instance service accounts follow least privilege');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        name: 'instance-1',
                        description: '',
                        zone:
                            'https://www.googleapis.com/compute/v1/projects/lofty-advantage-242315/zones/us-central1-a',
                        serviceAccounts: [
                            {
                                email: '413092707322-compute@developer.gserviceaccount.com',
                                scopes: [
                                    'https://www.googleapis.com/auth/devstorage.read_only',
                                    'https://www.googleapis.com/auth/logging.write'
                                ]
                            }
                        ]
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
})