var expect = require('chai').expect;
var plugin = require('./osLogin2FAEnabled');

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
                    data: 'testproj'
                }
            }
        }
    }
};

describe('osLogin2FAEnabled', function () {
    describe('run', function () {

        it('should give unknown if an instance error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query instances');
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

            const cache = createCache([]);

            plugin.run(cache, {}, callback);
        });

        it('should fail when OS Login 2FA is not enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OS Login 2FA is not enabled for the the instance');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        id: "17198672",
                        name: "testing-instance",
                        zone: "https://www.googleapis.com/compute/v1/projects/test-dev/zones/us-central1-a",
                        metadata: { items: [] }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass when OS Login 2FA is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OS Login 2FA is enabled for the the instance');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        id: "321087009587",
                        name: "testing-instance2",
                        zone: "https://www.googleapis.com/compute/v1/projects/test-dev/zones/us-central1-a",
                        metadata: {
                            items: [
                                { key: 'enable-oslogin', value: 'TRUE' },
                                { key: 'enable-oslogin-2fa', value: 'TRUE' }
                            ]
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
})