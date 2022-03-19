var expect = require('chai').expect;
const snsValidSubscribers = require('./snsValidSubscribers');

const listSubscriptions = [
    {
        "SubscriptionArn": "arn:aws:sns:us-east-1:000011112222:Default_CloudWatch_Alarms_Topic:18c0d0b0-f39e-4ac8-8e08-88f239768f61",
        "Owner": "000011112222",
        "Protocol": "email",
        "Endpoint": "xyz@aquasec.com",
        "TopicArn": "arn:aws:sns:us-east-1:000011112222:Default_CloudWatch_Alarms_Topic"
    },
    {
        "SubscriptionArn": "arn:aws:sns:us-east-1:000011112222:aqua-cspm-sns-000011112222:1a1450c0-03bd-4feb-a99f-bba3ca0540e9",
        "Owner": "000011112222",
        "Protocol": "email",
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



describe('snsValidSubscribers', function () {
    describe('run', function () {
        it('should PASS if SNS subscription is wanted', function (done) {
            const cache = createCache([listSubscriptions[1]]);
            snsValidSubscribers.run(cache, { sns_unwanted_subscribers: 'xyz@aquasec.com' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SNS subscription is a wanted subscription');
                done();
            });
        });

        it('should FAIL if SNS subscription is unwanted', function (done) {
            const cache = createCache([listSubscriptions[0]]);
            snsValidSubscribers.run(cache, { sns_unwanted_subscribers: 'xyz@aquasec.com' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SNS subscription is an unwanted subscription');
                done();
            });
        });

        it('should PASS if no SNS subscriptions found', function (done) {
            const cache = createCache([]);
            snsValidSubscribers.run(cache, { sns_unwanted_subscribers: 'xyz@aquasec.com' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SNS subscriptions Found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for SNS subscriptions', function (done) {
            const cache = createErrorCache();
            snsValidSubscribers.run(cache, { sns_unwanted_subscribers: 'xyz@aquasec.com' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SNS subscriptions');
                done();
            });
        });
    });
});