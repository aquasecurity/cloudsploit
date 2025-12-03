var expect = require('chai').expect;
const ecsFargatePlatformVersion = require('./ecsFargatePlatformVersion');

const listClusters = [
    'arn:aws:ecs:us-east-1:112233445566:cluster/test-cluster',
    'arn:aws:ecs:us-east-1:112233445566:cluster/another-cluster'
];

const createCache = (clusters, servicesMap, describeServicesMap) => {
    var cache = {
        ecs: {
            listClusters: {
                'us-east-1': {
                    data: clusters || []
                }
            },
            listServices: {
                'us-east-1': {}
            },
            describeServices: {
                'us-east-1': {}
            }
        }
    };

    if (clusters && clusters.length) {
        for (var clusterArn of clusters) {
            if (servicesMap && servicesMap[clusterArn]) {
                cache.ecs.listServices['us-east-1'][clusterArn] = {
                    data: servicesMap[clusterArn]
                };
            } else {
                cache.ecs.listServices['us-east-1'][clusterArn] = {
                    data: []
                };
            }
        }
    }

    if (describeServicesMap) {
        for (var serviceArn in describeServicesMap) {
            cache.ecs.describeServices['us-east-1'][serviceArn] = {
                data: describeServicesMap[serviceArn]
            };
        }
    }

    return cache;
};

const createErrorCache = () => {
    return {
        ecs: {
            listClusters: {
                'us-east-1': {
                    err: {
                        message: 'error listing clusters'
                    }
                }
            }
        }
    };
};

describe('ecsFargatePlatformVersion', function () {
    describe('run', function () {
        it('should PASS if no clusters found', function (done) {
            const cache = createCache([], {}, {});
            ecsFargatePlatformVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ECS clusters present');
                done();
            });
        });

        it('should PASS if no Fargate services found', function (done) {
            const servicesMap = {
                'arn:aws:ecs:us-east-1:112233445566:cluster/test-cluster': [
                    'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service'
                ]
            };
            const describeServicesMap = {
                'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service': {
                    services: [{
                        serviceName: 'my-service',
                        serviceArn: 'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service',
                        launchType: 'EC2'
                    }]
                }
            };
            const cache = createCache([listClusters[0]], servicesMap, describeServicesMap);
            ecsFargatePlatformVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ECS Fargate services found');
                done();
            });
        });

        it('should PASS if Linux Fargate service uses LATEST platform version', function (done) {
            const servicesMap = {
                'arn:aws:ecs:us-east-1:112233445566:cluster/test-cluster': [
                    'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service'
                ]
            };
            const describeServicesMap = {
                'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service': {
                    services: [{
                        serviceName: 'my-service',
                        serviceArn: 'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service',
                        launchType: 'FARGATE',
                        platformVersion: 'LATEST',
                        platformFamily: 'LINUX'
                    }]
                }
            };
            const cache = createCache([listClusters[0]], servicesMap, describeServicesMap);
            ecsFargatePlatformVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('using the latest platform version');
                done();
            });
        });

        it('should FAIL if Linux Fargate service uses 1.3.0 platform version', function (done) {
            const servicesMap = {
                'arn:aws:ecs:us-east-1:112233445566:cluster/test-cluster': [
                    'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service'
                ]
            };
            const describeServicesMap = {
                'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service': {
                    services: [{
                        serviceName: 'my-service',
                        serviceArn: 'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service',
                        launchType: 'FARGATE',
                        platformVersion: '1.3.0',
                        platformFamily: 'LINUX'
                    }]
                }
            };
            const cache = createCache([listClusters[0]], servicesMap, describeServicesMap);
            ecsFargatePlatformVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is not using the latest platform version');
                done();
            });
        });

        it('should PASS if Windows Fargate service uses LATEST platform version', function (done) {
            const servicesMap = {
                'arn:aws:ecs:us-east-1:112233445566:cluster/test-cluster': [
                    'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service'
                ]
            };
            const describeServicesMap = {
                'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service': {
                    services: [{
                        serviceName: 'my-service',
                        serviceArn: 'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service',
                        launchType: 'FARGATE',
                        platformVersion: 'LATEST',
                        platformFamily: 'WINDOWS_SERVER'
                    }]
                }
            };
            const cache = createCache([listClusters[0]], servicesMap, describeServicesMap);
            ecsFargatePlatformVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('using the latest platform version');
                done();
            });
        });

        it('should FAIL if Fargate service has no platform version configured', function (done) {
            const servicesMap = {
                'arn:aws:ecs:us-east-1:112233445566:cluster/test-cluster': [
                    'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service'
                ]
            };
            const describeServicesMap = {
                'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service': {
                    services: [{
                        serviceName: 'my-service',
                        serviceArn: 'arn:aws:ecs:us-east-1:112233445566:service/test-cluster/my-service',
                        launchType: 'FARGATE',
                        platformFamily: 'LINUX'
                    }]
                }
            };
            const cache = createCache([listClusters[0]], servicesMap, describeServicesMap);
            ecsFargatePlatformVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is not using the latest platform version');
                done();
            });
        });

        it('should UNKNOWN if unable to list clusters', function (done) {
            const cache = createErrorCache();
            ecsFargatePlatformVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query');
                done();
            });
        });
    });
});

