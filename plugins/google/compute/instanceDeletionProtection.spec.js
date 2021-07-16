var expect = require('chai').expect;
var plugin = require('./instanceDeletionProtection');

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

describe('instanceDeletionProtection', function () {
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

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if instance deletion protection is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance deletion protection is disabled');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": "1074579276103575670",
                        "creationTimestamp": "2019-09-25T14:05:30.014-07:00",
                        "name": "instance-2",
                        "description": "",
                        "tags": {
                            "fingerprint": "42WmSpB8rSM="
                        },
                        "canIpForward": false,
                        "labelFingerprint": "42WmSpB8rSM=",
                        "startRestricted": false,
                        "deletionProtection": false,
                        "kind": "compute#instance"
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if instance deletion protection is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Instance deletion protection is enabled');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": "1074579276103575670",
                        "creationTimestamp": "2019-09-25T14:05:30.014-07:00",
                        "name": "instance-2",
                        "description": "",
                        "tags": {
                            "fingerprint": "42WmSpB8rSM="
                        },
                        "canIpForward": false,
                        "labelFingerprint": "42WmSpB8rSM=",
                        "startRestricted": false,
                        "deletionProtection": true,
                        "kind": "compute#instance"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
})