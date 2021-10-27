const expect = require('chai').expect;
var mqAutoMinorVersionUpgrade = require('./mqAutoMinorVersionUpgrade');

const listBrokers = [
    {
        BrokerArn: 'arn:aws:mq:us-east-1:000111222333:broker:myBr1:b-943d9442-2bd9-4caa-b1fb-882451bcbb39',
        BrokerId: 'b-943d9442-2bd9-4caa-b1fb-882451bcbb39',
        BrokerName: 'myBr1',
        BrokerState: 'RUNNING',
        Created: "2021-10-11T09:23:08.234Z",
        DeploymentMode: 'SINGLE_INSTANCE',
        EngineType: 'ActiveMQ',
        HostInstanceType: 'mq.t3.micro'
    }
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
            "Endpoints": [Array],
            "IpAddress": '54.161.226.30'
            }
        ],
        "BrokerName": 'myBr1',
        "BrokerState": 'RUNNING',
    },
    {
        "AuthenticationStrategy": 'simple',
        "AutoMinorVersionUpgrade": false,
        "BrokerArn": 'arn:aws:mq:us-east-1:000111222333:broker:MyBroker12:b-127b45ef-fa90-40f4-bf8b-5a7c19b66cad',
        "BrokerId": 'b-127b45ef-fa90-40f4-bf8b-5a7c19b66cad',
        "BrokerInstances": [
            {
            "ConsoleURL": 'https://b-127b45ef-fa90-40f4-bf8b-5a7c19b66cad-1.mq.us-east-1.amazonaws.com:8162',     
            "Endpoints": [Array],
            "IpAddress": '54.161.226.30'
            }
        ],
        "BrokerName": 'myBr1',
        "BrokerState": 'RUNNING',
    }
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
                        data: describeBroker
                    }
                }
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


describe('mqAutoMinorVersionUpgrade', function () {
    describe('run', function () {

        it('should PASS if MQ auto version upgrade enabled', function (done) {
            const cache = createCache(listBrokers, describeBroker[0]);
            mqAutoMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if MQ auto version upgrade not enabled', function (done) {
            const cache = createCache(listBrokers, describeBroker[1]);
            mqAutoMinorVersionUpgrade.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no MQ brokers found', function (done) {
            const cache = createCache([]);
            mqAutoMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list MQ Brokers', function (done) {
            const cache = createCache(listBrokers, describeBroker[0], { message: 'error listing MQ brokers'});
            mqAutoMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list of MQ brokers not found', function (done) {
            const cache = createNullCache();
            mqAutoMinorVersionUpgrade.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});