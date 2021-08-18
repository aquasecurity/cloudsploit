var expect = require('chai').expect;
var plugin = require('./deleteExpiredDeployments');

var failTime = new Date();
failTime.setMonth(failTime.getMonth() - 1);

const createCache = (err, data) => {
    return {
        deployments: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: [ { name: 'testproj' }]
                }
            }
        }
    }
};

describe('deleteExpiredDeployments', function () {
    describe('run', function () {
        it('should give unknown result if a deployment error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Deployment Manager deployments');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, { deployments_expiration_time: '20' }, callback);
        });

        it('should give passing result if no Deployement Manager deployments found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Deployment Manager deployments found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, { deployments_expiration_time: '20' }, callback);
        });

        it('should give passing result if Deployment Manager deployment has not expired', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Deployment Manager deployment was created');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "2251375723239485948",
                        "name": "wordpress-1",
                        "operation": {
                          "id": "0",
                          "name": "operation-1628245779848-5c8e183509e02-53ff2030-53da6f15",
                          "operationType": "insert",
                          "targetId": "2251375723239485948",
                          "status": "DONE",
                          "progress": 100,
                          "insertTime": "1969-12-31T16:00:00.000-08:00",
                          "startTime": "2021-08-06T03:29:40.293-07:00",
                          "endTime": "2021-08-06T03:30:50.983-07:00",
                          "kind": "deploymentmanager#operation"
                        },
                        "fingerprint": "NG5zUVDkJK9BFxE-qP31iA==",
                        "insertTime": new Date(),
                        "updateTime": "2021-08-06T03:30:50.865-07:00",
                    }
                      
                ]
            );

            plugin.run(cache, { deployments_expiration_time: '0' }, callback);
        });

        it('should give failing result if Deployment Manager deployment has expired', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('has expired');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "2251375723239485948",
                        "name": "wordpress-1",
                        "operation": {
                            "id": "0",
                            "name": "operation-1628245779848-5c8e183509e02-53ff2030-53da6f15",
                            "operationType": "insert",
                            "targetId": "2251375723239485948",
                            "status": "DONE",
                            "progress": 100,
                            "insertTime": "1969-12-31T16:00:00.000-08:00",
                            "startTime": "2021-08-06T03:29:40.293-07:00",
                            "endTime": "2021-08-06T03:30:50.983-07:00",
                            "kind": "deploymentmanager#operation"
                        },
                        "fingerprint": "NG5zUVDkJK9BFxE-qP31iA==",
                        "insertTime": failTime,
                        "updateTime": "2021-08-06T03:30:50.865-07:00",
                    }
                ]
            );

            plugin.run(cache, { deployments_expiration_time: '20' }, callback);
        });

        it('should give nothing if deployment name or insertTime is not provided', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.equal(0);
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "2251375723239485948",
                        "operation": {
                            "id": "0",
                            "name": "operation-1628245779848-5c8e183509e02-53ff2030-53da6f15",
                            "operationType": "insert",
                            "targetId": "2251375723239485948",
                            "status": "DONE",
                            "progress": 100,
                            "insertTime": "1969-12-31T16:00:00.000-08:00",
                            "startTime": "2021-08-06T03:29:40.293-07:00",
                            "endTime": "2021-08-06T03:30:50.983-07:00",
                            "kind": "deploymentmanager#operation"
                        },
                        "fingerprint": "NG5zUVDkJK9BFxE-qP31iA==",
                        "insertTime": failTime,
                        "updateTime": "2021-08-06T03:30:50.865-07:00",
                    }
                ]
            );

            plugin.run(cache, { deployments_expiration_time: '20' }, callback);
        });
    });
});