var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instanceLeastPrivilege');

const createCache = (instanceData, error) => {
    return {
        instances: {
            compute: {
                list: {
                    'us-central1-a': {
                        data: instanceData,
                        err: error
                    }
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: 'test-proj'
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
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.equal('Unable to query compute instances');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass no VM Instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No instances found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail with full access service account', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance Service account has full access');
                expect(results[0].region).to.equal('us-central1');
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
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass with no full access service account', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Instance Service account follows least privilege');
                expect(results[0].region).to.equal('us-central1');
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