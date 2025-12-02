var expect = require('chai').expect;
const ecsServiceAssignPublicIpDisabled = require('./ecsServiceAssignPublicIpDisabled');

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

    if (clusters && clusters.length && servicesMap) {
        for (var clusterArn of clusters) {
            if (servicesMap[clusterArn]) {
                cache.ecs.listServices['us-east-1'][clusterArn] = {
                    data: servicesMap[clusterArn]
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

describe('ecsServiceAssignPublicIpDisabled', function () {
    describe('run', function () {
        it('should PASS if no clusters found', function (done) {
            const cache = createCache([], {}, {});
            ecsServiceAssignPublicIpDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ECS clusters found');
                done();
            });
        });

        it('should PASS if no services found', function (done) {
            const cache = createCache(listClusters, {}, {});
            ecsServiceAssignPublicIpDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ECS services found in cluster');
                done();
            });
        });

        it('should PASS if service has assignPublicIp set to DISABLED', function (done) {
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
                        networkConfiguration: {
                            awsvpcConfiguration: {
                                assignPublicIp: 'DISABLED',
                                subnets: ['subnet-12345'],
                                securityGroups: ['sg-12345']
                            }
                        }
                    }]
                }
            };
            const cache = createCache([listClusters[0]], servicesMap, describeServicesMap);
            ecsServiceAssignPublicIpDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('assignPublicIp set to DISABLED');
                done();
            });
        });

        it('should FAIL if service has assignPublicIp set to ENABLED', function (done) {
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
                        networkConfiguration: {
                            awsvpcConfiguration: {
                                assignPublicIp: 'ENABLED',
                                subnets: ['subnet-12345'],
                                securityGroups: ['sg-12345']
                            }
                        }
                    }]
                }
            };
            const cache = createCache([listClusters[0]], servicesMap, describeServicesMap);
            ecsServiceAssignPublicIpDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('assignPublicIp set to ENABLED');
                done();
            });
        });

        it('should UNKNOWN if unable to list clusters', function (done) {
            const cache = createErrorCache();
            ecsServiceAssignPublicIpDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query');
                done();
            });
        });
    });
});

