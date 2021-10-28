const expect = require('chai').expect;
var mqDeploymentMode = require('./mqDeploymentMode');

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
    },
    {
        BrokerArn: 'arn:aws:mq:us-east-1:000111222333:broker:myBr12:b-b80de4cb-bc4d-4b7f-813b-8e0143927aac',
        BrokerId: 'b-b80de4cb-bc4d-4b7f-813b-8e0143927aac',
        BrokerName: 'myBr12',
        BrokerState: 'RUNNING',
        Created: '2021-10-28T07:54:35.000Z',
        DeploymentMode: 'ACTIVE_STANDBY_MULTI_AZ',
        EngineType: 'ActiveMQ',
        HostInstanceType: 'mq.t3.micro'
      }
];

const createCache = (listBrokers, listErr, getErr) => {
    var broker = (listBrokers && listBrokers.length) ? listBrokers[0].BrokerId : null;
    return {
        mq: {
            listBrokers: {
                'us-east-1': {
                    err: listErr,
                    data: listBrokers
                }
            },
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


describe('mqDeploymentMode', function () {
    describe('run', function () {

        it('should PASS if MQ Deployment Mode enabled', function (done) {
            const cache = createCache([listBrokers[1]]);
            mqDeploymentMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if MQ Deployment Mode not enabled', function (done) {
            const cache = createCache([listBrokers[0]]);
            mqDeploymentMode.run(cache, { }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no MQ brokers found', function (done) {
            const cache = createCache([]);
            mqDeploymentMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list MQ Brokers', function (done) {
            const cache = createCache(listBrokers, { message: 'error listing MQ brokers'});
            mqDeploymentMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if list of MQ brokers not found', function (done) {
            const cache = createNullCache();
            mqDeploymentMode.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});