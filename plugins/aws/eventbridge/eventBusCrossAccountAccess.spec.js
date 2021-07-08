const expect = require('chai').expect;
var eventBusCrossAccountAccess = require('./eventBusCrossAccountAccess');

const listEventBuses = [
    {
        Name: 'test-bus',
        Arn: 'arn:aws:events:us-east-1:111111111111:event-bus/test-bus',
        Policy: '{"Version":"2012-10-17","Statement":[{"Sid":"allow_account_to_put_events","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::211111111111:user/y"},"Action":"events:PutEvents","Resource":"arn:aws:events:us-east-1:111111111111:event-bus/test-bus"}]}'
    },
    {
        Name: 'test-bus',
        Arn: 'arn:aws:events:us-east-1:111111111111:event-bus/test-bus',
        Policy: '{"Version":"2012-10-17","Statement":[{"Sid":"allow_account_to_put_events","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/x"},"Action":"events:PutEvents","Resource":"arn:aws:events:us-east-1:111111111111:event-bus/test-bus"}]}'
    },
    {
        Name: 'test-bus',
        Arn: 'arn:aws:events:us-east-1:111111111111:event-bus/test-bus',
    },
];

const createCache = (eventBus, eventBusErr) => {
    return {
        eventbridge: {
            listEventBuses: {
                'us-east-1': {
                    data: eventBus,
                    err: eventBusErr
                }
            }
        },
        sts: {
            getCallerIdentity: {
                'us-east-1':{
                    data: '111111111111'
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        eventbridge: {
            listEventBuses: {
                'us-east-1': null
            }
        }
    };
};

describe('eventBusCrossAccountAccess', function () {
    describe('run', function () {

        it('should PASS if Event Bus has cross-account access policy attached', function (done) {
            const cache = createCache([listEventBuses[0]]);
            eventBusCrossAccountAccess.run(cache, {"whitelisted_aws_account_principals":['arn:aws:iam::211111111111:user/y']}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should FAIL if Event Bus does not have cross-account access policy attached', function (done) {
            const cache = createCache([listEventBuses[1]]);
            eventBusCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should FAIL if no Event Bus policy found', function (done) {
            const cache = createCache(listEventBuses[2]);
            eventBusCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if no Event Bus found', function (done) {
            const cache = createCache([]);
            eventBusCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe RDS instances', function (done) {
            const cache = createCache([], { message: 'Unable to describe instances' });
            eventBusCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should not return anything if describe DB instances response not found', function (done) {
            const cache = createNullCache();
            eventBusCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});