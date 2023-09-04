const expect = require('chai').expect;
const mqNetworkOfBrokers = require('./mqNetworkOfBrokers');

const listBrokers = [
    {
        BrokerArn: 'arn:aws:mq:us-east-1:000111222333:broker:myBr1:b-5bf97c6e-1ce8-48da-9200-ecd32b861be9',
        BrokerId: 'b-5bf97c6e-1ce8-48da-9200-ecd32b861be9',
        BrokerName: 'myBr1',
        BrokerState: 'RUNNING',
        Created: '2021-10-12T10:28:35.851Z',
        DeploymentMode: 'SINGLE_INSTANCE',
        EngineType: 'ActiveMQ',
        HostInstanceType: 'mq.t3.micro'
    },
    {
        BrokerArn: 'arn:aws:mq:us-east-1:000111222333:broker:myBr1:b-5bf97c6e-1ce8-48da-9200-ecd32b861be8',
        BrokerId: 'b-5bf97c6e-1ce8-48da-9200-ecd32b861be8',
        BrokerName: 'myBr2',
        BrokerState: 'RUNNING',
        Created: '2021-10-12T10:28:35.851Z',
        DeploymentMode: 'SINGLE_INSTANCE',
        EngineType: 'ActiveMQ',
        HostInstanceType: 'mq.t3.micro'
    },
];

const createCache = (listBrokers, listErr) => {
    return {
        mq: {
            listBrokers: {
                'us-east-1': {
                    err: listErr,
                    data: listBrokers
                }
            }
        }
    };
};

describe('mqNetworkOfBrokers', function () {
    describe('run', function () {

        it('should PASS if broker is part of a full mesh network', function (done) {
            const cache = createCache(listBrokers);
            mqNetworkOfBrokers.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[1].status).to.equal(0);
                expect(results[1].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if broker is not part of a full mesh network', function (done) {
            const listBrokersWithNonMeshBroker = [
                {
                    BrokerArn: 'arn:aws:mq:us-east-1:000111222333:broker:myBr1:b-5bf97c6e-1ce8-48da-9200-ecd32b861be9',
                    BrokerId: 'b-5bf97c6e-1ce8-48da-9200-ecd32b861be9',
                    BrokerName: 'singleBroker', 
                    BrokerState: 'RUNNING',
                    Created: '2021-10-12T10:28:35.851Z',
                    DeploymentMode: 'SINGLE_INSTANCE',
                    EngineType: 'ActiveMQ',
                    HostInstanceType: 'mq.t3.micro'
                }
            ];
            const cache = createCache(listBrokersWithNonMeshBroker);
            mqNetworkOfBrokers.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no MQ brokers found', function (done) {
            const cache = createCache([]);
            mqNetworkOfBrokers.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list MQ Brokers', function (done) {
            const cache = createCache(listBrokers, { message: 'error listing MQ brokers' });
            mqNetworkOfBrokers.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
