const expect = require('chai').expect;
const mqLatestEngineVersion = require('./mqLatestEngineVersion');

const listBrokers = [
    {
        BrokerArn: 'arn:aws:mq:us-east-1:000111222333:broker:myBr1:b-943d9442-2bd9-4caa-b1fb-882451bcbb39',
        BrokerId: 'b-943d9442-2bd9-4caa-b1fb-882451bcbb39',
        BrokerName: 'myBr1',
        BrokerState: 'RUNNING',
        Created: "2021-10-11T09:23:08.234Z",
        DeploymentMode: 'SINGLE_INSTANCE',
        EngineType: 'ACTIVEMQ',
        HostInstanceType: 'mq.t3.micro',
        EngineVersion: '5.17.3'
    },
    {
        BrokerArn: 'arn:aws:mq:us-east-1:000111222333:broker:myBr2:b-943d9442-2bd9-4caa-b1fb-882451bcbb40',
        BrokerId: 'b-943d9442-2bd9-4caa-b1fb-882451bcbb40',
        BrokerName: 'myBr2',
        BrokerState: 'RUNNING',
        Created: "2021-09-15T08:45:20.123Z",
        DeploymentMode: 'ACTIVE_STANDBY_MULTI_AZ',
        EngineType: 'ACTIVEMQ',
        HostInstanceType: 'mq.t3.small',
        EngineVersion: '5.16.2'
    },
];

const describeBroker = [
    {
        "AuthenticationStrategy": 'simple',
        "AutoMinorVersionUpgrade": true,
        "BrokerArn": 'arn:aws:mq:us-east-1:000111222333:broker:MyBroker12:b-127b45ef-fa90-40f4-bf8b-5a7c19b66cad',
        "BrokerId": 'b-127b45ef-fa90-40f4-bf8b-5a7c19b66cad',
        "BrokerInstances": [
            {
                "ConsoleURL": 'https://b-127b45ef-fa90-40f4-bf8b-5a7c19b66cad-1.mq.us-east-1.amazonaws.com:8162',     
                "Endpoints": ['ssl://b-127b45ef-fa90-40f4-bf8b-5a7c19b66cad.mq.us-east-1.amazonaws.com:61617'],
                "IpAddress": '54.161.226.30'
            }
        ],
        "BrokerName": 'myBr1',
        "BrokerState": 'RUNNING',
        "EngineVersion": '5.17.3'
    },
    {
        "AuthenticationStrategy": 'simple',
        "AutoMinorVersionUpgrade": false,
        "BrokerArn": 'arn:aws:mq:us-east-1:000111222333:broker:MyBroker12:b-127b45ef-fa90-40f4-bf8b-5a7c19b66cae',
        "BrokerId": 'b-127b45ef-fa90-40f4-bf8b-5a7c19b66cae',
        "BrokerInstances": [
            {
                "ConsoleURL": 'https://b-127b45ef-fa90-40f4-bf8b-5a7c19b66cae-1.mq.us-east-1.amazonaws.com:8162',     
                "Endpoints": ['ssl://b-127b45ef-fa90-40f4-bf8b-5a7c19b66cae.mq.us-east-1.amazonaws.com:61617'],
                "IpAddress": '54.161.226.31'
            }
        ],
        "BrokerName": 'myBr2',
        "BrokerState": 'RUNNING',
        "EngineVersion": '5.16.2'
    },
];

const createCache = (listBrokers, describeBroker, listErr, getErr) => {
    var broker = (listBrokers && listBrokers.length) ? listBrokers[0].BrokerId : null;

    return {
        mq: {
            listBrokers: {
                'us-east-1': {
                    err: listErr,
                    data: listBrokers
                }
            },
            describeBroker: {
                'us-east-1': {
                    [broker]: {
                        err: getErr,
                        data: describeBroker[0]
                    }
                },
            }
        }
    };
};
const createNullCache = () => {
    return {
        mq: {
            listBrokers: {
                'us-east-1': null
            }
        }
    };
};
describe('mqLatestEngineVersion', function () {
    describe('run', function () {

        it('should PASS if broker uses the latest ActiveMQ version', function (done) {
            const cache = createCache([listBrokers[0]], [describeBroker[0]], null, null);
            mqLatestEngineVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if broker does not use the latest ActiveMQ version', function (done) {
            const cache = createCache([listBrokers[1]],[ describeBroker[1]], null, null);
            mqLatestEngineVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no MQ brokers found', function (done) {
            const cache = createCache([], [], null, null);
            mqLatestEngineVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list MQ Brokers', function (done) {
            const cache = createCache(listBrokers, describeBroker, { message: 'error listing MQ brokers'}, null);
            mqLatestEngineVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list mq brokers response not found', function (done) {
            const cache = createNullCache();
            mqLatestEngineVersion.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
