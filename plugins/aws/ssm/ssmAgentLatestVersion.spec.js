var assert = require('assert');
var expect = require('chai').expect;
var ssmAgentLatestVersion = require('./ssmAgentLatestVersion')

const createCache = (instances) => {
    return {
        ssm: {
            describeInstanceInformation: {
                'us-east-1': {
                    data: instances
                }
            }
        },
        sts: {
            getCallerIdentity: {
                data: '012345678911'
            }
        }
    };
};

const createEmptyCache = () => {
    return {
        ssm: {
            describeInstanceInformation: {
                'us-east-1': {
                    data: []
                }
            }
        },
        sts: {
            getCallerIdentity: {
                data: '012345678911'
            }
        }
    };
};

const createErrorCache = () => {
    return {
        ssm: {
            describeInstanceInformation: {
                'us-east-1': {
                    err: {
                        message: 'bad error'
                    }
                }
            }
        },
        sts: {
            getCallerIdentity: {
                data: '012345678911'
            }
        }
    };
};

const createNullCache = () => {
    return {
        ssm: {
            describeInstanceInformation: null,
        },
        sts: {
            getCallerIdentity: {
                data: '012345678911'
            }
        }
    };
};

describe('ssmAgentLatestVersion', function () {
    describe('run', function () {
        it('should PASS if there are no installations', function (done) {
            const cache = createCache([]);
            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if there are no installations found', function (done) {
            const cache = createEmptyCache();
            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if online Linux instance has in-date agent', function (done) {
            const cache = createCache([
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Linux',
                    PingStatus: 'Online',
                    IsLatestVersion: true
                }
            ]);
            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if all instances are Microsoft', function (done) {
            const cache = createCache([
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Microsoft',
                    PingStatus: 'Online',
                    IsLatestVersion: true
                },
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Microsoft',
                    PingStatus: 'Offline',
                    IsLatestVersion: true
                }
            ]);
            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if all instances are offline', function (done) {
            const cache = createCache([
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Linux',
                    PingStatus: 'Offline',
                    IsLatestVersion: false
                },
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Microsoft',
                    PingStatus: 'Offline',
                    IsLatestVersion: false
                }
            ]);
            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if online Linux instance has out-of-date agent', function (done) {
            const cache = createCache([
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Linux',
                    PingStatus: 'Online',
                    IsLatestVersion: false
                }
            ]);
            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL with 19 results if 19 online Linux instances have out-of-date agent', function (done) {
            const cache = createCache(Array(19).fill(
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Linux',
                    PingStatus: 'Online',
                    IsLatestVersion: false
                }
            ));

            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(19);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL with 1 result if 21 online Linux instances have out-of-date agent', function (done) {
            const cache = createCache(Array(21).fill(
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Linux',
                    PingStatus: 'Online',
                    IsLatestVersion: false
                }
            ));

            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS with 19 results if 19 online Linux instances have in-date agent', function (done) {
            const cache = createCache(Array(19).fill(
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Linux',
                    PingStatus: 'Online',
                    IsLatestVersion: true
                }
            ));

            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(19);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS with 1 result if 21 online Linux instances have in-date agent', function (done) {
            const cache = createCache(Array(21).fill(
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Linux',
                    PingStatus: 'Online',
                    IsLatestVersion: true
                }
            ));

            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS with 1 result if 21 online Linux instances have mixes of agents', function (done) {
            const cache = createCache(Array(11).fill(
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Linux',
                    PingStatus: 'Online',
                    IsLatestVersion: true
                }
            ).concat(Array(11).fill(
                {
                    InstanceId: 'i-abc1234',
                    PlatformType: 'Linux',
                    PingStatus: 'Online',
                    IsLatestVersion: false
                }
            )));

            ssmAgentLatestVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
    });
});
