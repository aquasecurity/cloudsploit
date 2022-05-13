var expect = require('chai').expect;
const eventsInUse = require('./eventsInUse');

const listRules = [
    {
        Name: 'AutoScalingManagedRule',
        Arn: 'arn:aws:events:us-east-1:000011112222:rule/AutoScalingManagedRule',
        EventPattern: '{"source":["aws.ec2"],"detail-type":["EC2 Instance Rebalance Recommendation","EC2 Spot Instance Interruption Warning"]}',
        State: 'ENABLED',
        Description: 'This rule is used to route Instance notifications to EC2 Auto Scaling',
        ManagedBy: 'autoscaling.amazonaws.com',
        EventBusName: 'default'
    },
    {}
];

const createCache = (data, err) => {
    return {
        eventbridge: {
            listRules: {
                'us-east-1': {
                    data: data,
                    err: err
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        eventbridge: {
            listRules: {
                'us-east-1': null,
            },
        },
    };
};

describe('eventsInUse', function () {
    describe('run', function () {
        it('should PASS if EventBridge event rules are in use', function (done) {
            const cache = createCache([listRules[0]]);
            eventsInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('EventBridge event rules are in use')
                done();
            });
        });

        it('should FAIL if EventBridge event rules are not in use', function (done) {
            const cache = createCache(listRules[1]);
            eventsInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('EventBridge event rules are not in use')
                done();
            });
        });

        it('should UNKNOWN if Unable to list EventBridge events rules', function (done) {
            const cache = createCache(null, { message: 'Unable to list EventBridge event rules' });
            eventsInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list EventBridge event rules')
                done();
            });
        });

        it('should not return any results if list EventBridge event rules response not found', function (done) {
            const cache = createNullCache();
            eventsInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
