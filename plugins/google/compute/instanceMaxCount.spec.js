var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instanceMaxCount');

const createCache = (instanceData, error) => {
    return {
        instances: {
            compute: {
                list: {
                    'us-east1-b': {
                        data: instanceData,
                        err: error
                    }
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

describe('instanceMaxCount', function () {
    describe('run', function () {

        it('should pass if no VM Instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if VM instance count is not within regional threshold', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('exceeding');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "1111111",
                        "creationTimestamp": "2019-10-04T13:44:44.117-07:00",
                        "name": "instance-3",
                        "description": "",
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/machineTypes/n1-standard-1",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/instances/instance-3",
                    },
                    {
                        "kind": "compute#instance",
                        "id": "1111111",
                        "creationTimestamp": "2019-10-04T13:44:44.117-07:00",
                        "name": "instance-2",
                        "description": "",
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/machineTypes/n1-standard-1",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/instances/instance-2",
                    }
                ],
                null
            );

            plugin.run(cache, {instance_count_region_threshold_us_east1: 1}, callback);
        })

        it('should pass if VM instance count is within regional threshold', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('are within the');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "45444",
                        "creationTimestamp": "2019-09-25T14:05:30.014-07:00",
                        "name": "instance-2",
                        "description": "",
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/machineTypes/g1-small",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b",
                        "canIpForward": false,
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/instances/instance-2",
                    }
                ]
            );

            plugin.run(cache, {instance_count_region_threshold_us_east1: 100}, callback);
        })

        it('should fail if VM instance count is not within global threshold', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[(results.length - 1)].status).to.equal(2);
                expect(results[(results.length - 1)].message).to.include('exceeding');
                expect(results[(results.length - 1)].region).to.equal('global');
                done()
            };
    
            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "1111111",
                        "creationTimestamp": "2019-10-04T13:44:44.117-07:00",
                        "name": "instance-3",
                        "description": "",
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/machineTypes/n1-standard-1",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/instances/instance-3",
                    },
                    {
                        "kind": "compute#instance",
                        "id": "1111111",
                        "creationTimestamp": "2019-10-04T13:44:44.117-07:00",
                        "name": "instance-2",
                        "description": "",
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/machineTypes/n1-standard-1",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/instances/instance-2",
                    }
                ],
                null
            );
    
            plugin.run(cache, {instance_count_global_threshold: 1}, callback);
        })
    
        it('should pass if VM instance count is within global threshold', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[(results.length - 1)].status).to.equal(0);
                expect(results[(results.length - 1)].message).to.include('are within the');
                expect(results[(results.length - 1)].region).to.equal('global');
                done()
            };
    
            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "45444",
                        "creationTimestamp": "2019-09-25T14:05:30.014-07:00",
                        "name": "instance-2",
                        "description": "",
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/machineTypes/g1-small",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b",
                        "canIpForward": false,
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-east1-b/instances/instance-2",
                    }
                ]
            );
    
            plugin.run(cache, {instance_count_global_threshold: 100}, callback);
        })

    })

});