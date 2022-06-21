var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instanceGroupAutoHealing');

const createCache = (instanceData, error) => {
    return {
        instanceGroupManagers: {
                list: {
                    'us-central1-a': {
                        data: instanceData,
                        err: error
                    }
                }
        },
        projects: {
            get: {
                'global': {
                    data: 'tets-proj'
                }
            }
        }
    }
};

describe('instanceGroupAutohealing', function () {
    describe('run', function () {
        const settings = { instance_desired_machine_types: 'e2-micro' };
        it('should give unknown if an instance group error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query instance groups');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                ['error']
            );

            plugin.run(cache, settings, callback);
        });

        it('should pass no VM Instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No instance groups found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, settings, callback);
        });

        it('should FAIL if instance group does not have auto healing enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance Group does not have auto healing enabled');
                done()
            };
            const cache = createCache(
                [
                    {
                        "id": '11111111',
                        "creationTimestamp": '2022-01-05T12:19:12.147-08:00',
                        "name": 'instance-group-1',
                        "description": '',
                        "zone": 'https://www.googleapis.com/compute/v1/projects/my-project-1/zones/us-central1-a',
                        "instanceGroup": 'https://www.googleapis.com/compute/v1/projects/my-project-1/zones/us-central1-a/instanceGroups/instance-group-1',
                        "baseInstanceName": 'instance-group-1',
                        "autoHealingPolicies": []
                    }
                ],
                null
            );

            plugin.run(cache, settings, callback);
        })

        it('should PASS if instance group has auto healing enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('Instance Group has auto healing enabled');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": '11111111',
                        "creationTimestamp": '2022-01-05T12:19:12.147-08:00',
                        "name": 'instance-group-1',
                        "description": '',
                        "zone": 'https://www.googleapis.com/compute/v1/projects/my-project-1/zones/us-central1-a',
                        "instanceGroup": 'https://www.googleapis.com/compute/v1/projects/my-project-1/zones/us-central1-a/instanceGroups/instance-group-1',
                        "baseInstanceName": 'instance-group-1',
                        "autoHealingPolicies": [
                            {
                                "healthCheck": 'https://www.googleapis.com/compute/v1/projects/my-project/global/healthChecks/hc-1',
                                "initialDelaySec": 300
                              }
                        ]
                    }
                ]
            );

            plugin.run(cache, settings, callback);
        })

    })
});