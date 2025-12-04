var expect = require('chai').expect;
const ecsServicePublicIpDisabled = require('./ecsServicePublicIpDisabled');

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

describe('ecsServicePublicIpDisabled', function () {
    describe('run', function () {
        it('should PASS if no clusters found', function (done) {
            const cache = createCache([], {}, {});
            ecsServicePublicIpDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ECS clusters found');
                done();
            });
        });

        it('should PASS if no services found', function (done) {
            const cache = createCache(listClusters, {}, {});
            ecsServicePublicIpDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No ECS services found in cluster');
                done();
            });
        });

        it('should PASS if service has assignPublicIp set to disabled', function (done) {
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
            ecsServicePublicIpDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has assignPublicIp set to disabled');
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
            ecsServicePublicIpDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have assignPublicIp set to disabled');
                done();
            });
        });

        it('should UNKNOWN if unable to list clusters', function (done) {
            const cache = createErrorCache();
            ecsServicePublicIpDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query');
                done();
            });
        });
    });
});

