const expect = require('chai').expect;
var mqDesiredInstanceType = require('./mqDesiredInstanceType');

const listBrokers = [
    {
        BrokerArn: 'arn:aws:mq:us-east-1:000011112222:broker:Mybr1:b-64f1b066-9604-46c0-ad14-b6fe482b29a0',
        BrokerId: 'b-64f1b066-9604-46c0-ad14-b6fe482b29a0',
        BrokerName: 'Mybr1',
        BrokerState: 'RUNNING',
        Created: '2021-11-01T07:42:35.629Z',
        DeploymentMode: 'SINGLE_INSTANCE',
        EngineType: 'ActiveMQ',
        HostInstanceType: 'mq.t3.micro'
      },
      {
        BrokerArn: 'arn:aws:mq:us-east-1:000011112222:broker:MyBr2:b-ec84403c-f14b-438b-889b-e931706aaae6',
        BrokerId: 'b-ec84403c-f14b-438b-889b-e931706aaae6',
        BrokerName: 'MyBr2',
        BrokerState: 'RUNNING',
        Created: '2021-11-01T07:43:08.697Z',
        DeploymentMode: 'SINGLE_INSTANCE',
        EngineType: 'ActiveMQ',
        HostInstanceType: 'mq.m5.large'
      }
];


const createCache = (listBrokers) => {
    return {
        mq: {
            listBrokers: {
                'us-east-1': {
                    data: listBrokers
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        mq: {
            listBrokers: {
                'us-east-1': {
                    err: {
                        message: 'error listing mq functions'
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

describe('mqDesiredInstanceType', function () {
    describe('run', function () {

        it('should PASS if brokers have the desired instance type', function (done) {
            const cache = createCache([listBrokers[0]]);
            mqDesiredInstanceType.run(cache, { mq_desired_instance_type: 'mq.t3.micro'  }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Broker has desired instance type');
                done();
            });
        });

        it('should FAIL if broker does not have desired instance type', function (done) {
            const cache = createCache([listBrokers[1]]);
            mqDesiredInstanceType.run(cache, { mq_desired_instance_type: 'mq.t3.micro' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Broker does not have desired instance type')
                done();
            });
        });

        it('should PASS if no MQ brokers found', function (done) {
            const cache = createCache([]);
            mqDesiredInstanceType.run(cache, { mq_desired_instance_type: 'mq.m5.large' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No MQ brokers found');
                done();
            });
        });

        it('should UNKNOWN if unable to list MQ brokers', function (done) {
            const cache = createErrorCache();
            mqDesiredInstanceType.run(cache, { mq_desired_instance_type: 'mq.m5.large' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query MQ brokers');
                done();
            });
        });

        it('should not return anything if list mq brokers response not found', function (done) {
            const cache = createNullCache();
            mqDesiredInstanceType.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});