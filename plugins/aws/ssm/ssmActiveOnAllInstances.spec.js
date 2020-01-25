var assert = require('assert');
var expect = require('chai').expect;
var ssmActiveOnAllInstances = require('./ssmActiveOnAllInstances')

const createCache = (ec2s, ssms) => {
    return {
        ec2: {
            describeInstances: {
                'us-east-1': {
                    data: ec2s
                }
            }
        },
        ssm: {
            describeInstanceInformation: {
                'us-east-1': {
                    data: ssms
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

describe('ssmActiveOnAllInstances', function () {
    describe('run', function () {
        it('should PASS if there are no instance reservations', function (done) {
            const cache = createCache([]);
            ssmActiveOnAllInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if there are no instances', function (done) {
            const cache = createCache([
                {
                    Instances: []
                }
            ], []);
            ssmActiveOnAllInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if there are instances but no installations', function (done) {
            const cache = createCache([
                {
                    Instances: [
                        {
                            InstanceId: 'i-abc1234'
                        }
                    ]
                }
            ], []);
            ssmActiveOnAllInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if there are instances but no installations for that ID', function (done) {
            const cache = createCache([
                {
                    Instances: [
                        {
                            InstanceId: 'i-abc1234'
                        }
                    ]
                }
            ], [
                {
                    InstanceId: 'i-bcd1234',
                    PingStatus: 'Online'
                }
            ]);
            ssmActiveOnAllInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if there are instances with installations for that ID', function (done) {
            const cache = createCache([
                {
                    Instances: [
                        {
                            InstanceId: 'i-abc1234'
                        }
                    ]
                }
            ], [
                {
                    InstanceId: 'i-abc1234',
                    PingStatus: 'Online'
                }
            ]);
            ssmActiveOnAllInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if there are instances with offline installations for that ID', function (done) {
            const cache = createCache([
                {
                    Instances: [
                        {
                            InstanceId: 'i-abc1234'
                        }
                    ]
                }
            ], [
                {
                    InstanceId: 'i-abc1234',
                    PingStatus: 'Offline'
                }
            ]);
            ssmActiveOnAllInstances.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
    });
});
