var expect = require('chai').expect;
var mqBrokerPublicAccessibility = require('./mqBrokerPublicAccess');

const listBrokers = [
    {
        "BrokerArn": "arn:aws:mq:us-east-1:000011112222:broker:sadeed-br:b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4",
        "BrokerId": "b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4",
        "BrokerName": "sadeed-br",
        "BrokerState": "RUNNING",
        "Created": "2021-11-15T08:21:57.182000+00:00",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EngineType": "ActiveMQ",
        "HostInstanceType": "mq.t3.micro",
        "PubliclyAccessible": false
    },
    {
        "BrokerArn": "arn:aws:mq:us-east-1:000011112222:broker:public-br:b-b4cfface-0aa9-4922-b41d-07fab046cef3",
        "BrokerId": "b-b4cfface-0aa9-4922-b41d-07fab046cef3",
        "BrokerName": "public-br",
        "BrokerState": "RUNNING",
        "Created": "2021-11-15T09:58:29.997000+00:00",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EngineType": "ActiveMQ",
        "HostInstanceType": "mq.t3.micro",
        "PubliclyAccessible": true
    }
];

const describeBroker = [
    {
        "BrokerArn": "arn:aws:mq:us-east-1:000011112222:broker:sadeed-br:b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4",
        "BrokerId": "b-a67fb4c0-2f23-46cf-98cb-7015bd36e1b4",
        "BrokerName": "sadeed-br",
        "BrokerState": "RUNNING",
        "Created": "2021-11-15T08:21:57.182000+00:00",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EngineType": "ActiveMQ",
        "HostInstanceType": "mq.t3.micro",
        "PubliclyAccessible": false
    },
    {
        "BrokerArn": "arn:aws:mq:us-east-1:000011112222:broker:public-br:b-b4cfface-0aa9-4922-b41d-07fab046cef3",
        "BrokerId": "b-b4cfface-0aa9-4922-b41d-07fab046cef3",
        "BrokerName": "public-br",
        "BrokerState": "RUNNING",
        "Created": "2021-11-15T09:58:29.997000+00:00",
        "DeploymentMode": "SINGLE_INSTANCE",
        "EngineType": "ActiveMQ",
        "HostInstanceType": "mq.t3.micro",
        "PubliclyAccessible": true
    }
];

const createCache = (brokers, describeBroker, brokersErr, describeBrokerErr) => {
    var BrokerId = (brokers && brokers.length) ? brokers[0].BrokerId: null;
    return {
        mq: {
            listBrokers: {
                'us-east-1': {
                    err: brokersErr,
                    data: brokers
                },
            },
            describeBroker: {
                'us-east-1': {
                    [BrokerId]: {
                        data: describeBroker,
                        err: describeBrokerErr
                    }
                }
            }
        }
    };
};

describe('mqBrokerPublicAccessibility', function () {
    describe('run', function () {
        it('should PASS if MQ Broker is not publicly accessible', function (done) {
            const cache = createCache([listBrokers[0]], describeBroker[0]);
            mqBrokerPublicAccessibility.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('MQ Broker is not publicly accessible');
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if MQ Broker is publicly accessible', function (done) {
            const cache = createCache([listBrokers[1]], describeBroker[1]);
            mqBrokerPublicAccessibility.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
        });
        });

        it('should PASS if no MQ Broker found', function (done) {
            const cache = createCache([]);
            mqBrokerPublicAccessibility.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list MQ Broker', function (done) {
            const cache = createCache(null, null, { message: "Unable to list MQ Broker" }, null);
            mqBrokerPublicAccessibility.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe MQ broker', function (done) {
            const cache = createCache([listBrokers[0]], null, null, { message: "Unable to describe MQ broker" });
            mqBrokerPublicAccessibility.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});