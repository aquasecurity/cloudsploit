var expect = require('chai').expect;
const snsAppropriateSubscribers = require('./snsAppropriateSubscribers');

const listSubscriptions = [
    {
        "SubscriptionArn": "arn:aws:sns:us-east-1:000011112222:Default_CloudWatch_Alarms_Topic:18c0d0b0-f39e-4ac8-8e08-88f239768f61",
        "Owner": "000011112222",
        "Protocol": "email",
        "Endpoint": "makhtar.pucit@gmail.com",
        "TopicArn": "arn:aws:sns:us-east-1:000011112222:Default_CloudWatch_Alarms_Topic"
    },
    {
        "SubscriptionArn": "arn:aws:sns:us-east-1:000011112222:aqua-cspm-sns-000011112222:1a1450c0-03bd-4feb-a99f-bba3ca0540e9",
        "Owner": "000011112222",
        "Protocol": "email",
        "Endpoint": "sadeed1999@gmail.com",
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



describe('snsAppropriateSubscribers', function () {
    describe('run', function () {
        it('should PASS if SNS subscriber is appropriate for topic', function (done) {
            const cache = createCache([listSubscriptions[0]]);
            snsAppropriateSubscribers.run(cache, { sns_unwanted_subscribers_endpoint:'sadeed1999@gmail.com' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SNS subscription is not an unwanted subscription');
                done();
            });
        });

        it('should FAIL if SNS subscriber is unwanted for topic', function (done) {
            const cache = createCache([listSubscriptions[1]]);
            snsAppropriateSubscribers.run(cache, { sns_unwanted_subscribers_endpoint:'sadeed1999@gmail.com' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SNS subscription is an unwanted subscription');
                done();
            });
        });

        it('should PASS if no SNS subscriptions found', function (done) {
            const cache = createCache([]);
            snsAppropriateSubscribers.run(cache, { sns_unwanted_subscribers_endpoint:'sadeed1999@gmail.com' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SNS subscriptions Found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for SNS subscriptions', function (done) {
            const cache = createErrorCache();
            snsAppropriateSubscribers.run(cache, { sns_unwanted_subscribers_endpoint:'sadeed1999@gmail.com' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SNS subscriptions');
                done();
            });
        });
    });
});