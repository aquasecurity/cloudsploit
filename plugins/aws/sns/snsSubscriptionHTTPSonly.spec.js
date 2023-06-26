var expect = require('chai').expect;
const snsSubscriptionHTTPSonly = require('./snsSubscriptionHTTPSonly');

const listSubscriptions = [
    {
        "SubscriptionArn": "arn:aws:sns:us-east-1:000011112222:Default_CloudWatch_Alarms_Topic:18c0d0b0-f39e-4ac8-8e08-88f239768f61",
        "Owner": "000011112222",
        "Protocol": "https",
        "Endpoint": "xyz@aquasec.com",
        "TopicArn": "arn:aws:sns:us-east-1:000011112222:Default_CloudWatch_Alarms_Topic"
    },
    {
        "SubscriptionArn": "arn:aws:sns:us-east-1:000011112222:aqua-cspm-sns-000011112222:1a1450c0-03bd-4feb-a99f-bba3ca0540e9",
        "Owner": "000011112222",
        "Protocol": "http",
        "Endpoint": "xxz@aquasec.com",
        "TopicArn": "arn:aws:sns:us-east-1:000011112222:aqua-cspm-sns-000011112222"
    }
];

const createCache = (instances) => {
    return {
        sns: {
            listSubscriptions: {
                'us-east-1': {
                    data: instances
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        sns: {
            listSubscriptions: {
                'us-east-1': {
                    err: {
                        message: 'Error listing subscriptions'
                    }
                }
            }
        }
    };
};



describe('snsSubscriptionHTTPprotocol', function () {
    describe('run', function () {
        it('should PASS if SNS subscription is configure to use http protocol', function (done) {
            const cache = createCache([listSubscriptions[0]]);
            snsSubscriptionHTTPSonly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SNS subscription is using HTTPS protocol');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if SNS subscription is not configure to use http protocol', function (done) {
            const cache = createCache([listSubscriptions[1]]);
            snsSubscriptionHTTPSonly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SNS subscription is not using HTTPS protocol');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no SNS subscriptions found', function (done) {
            const cache = createCache([]);
            snsSubscriptionHTTPSonly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SNS subscriptions found');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for SNS subscriptions', function (done) {
            const cache = createErrorCache();
            snsSubscriptionHTTPSonly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SNS subscriptions');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
