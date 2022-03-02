const expect = require('chai').expect;
var eventBusPublicAccess = require('./eventBusPublicAccess');

const listEventBuses = [
    {
        Name: "default",
        Arn: "arn:aws:events:us-east-1:000011112222:event-bus/default",
        Policy: "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"allow_all_accounts_from_organization_to_put_events\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"events:PutEvents\",\"Resource\":\"arn:aws:events:us-east-1:000011112222:event-bus/default\",\"Condition\":{\"StringEquals\":{\"aws:PrincipalOrgID\":\"o-lcjto3x5wd\"}}}]}"
    },
    {
        Name: "mine1",
        Arn: "arn:aws:events:us-east-1:000011112222:event-bus/mine1",
        Policy: "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"allow_all_accounts_from_organization_to_put_events\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"000011112222\"},\"Action\":\"events:PutEvents\",\"Resource\":\"arn:aws:events:us-east-1:000011112222:event-bus/mine1\",\"Condition\":{\"StringEquals\":{\"aws:PrincipalOrgID\":\"o-lcjto3x5wd\"}}}]}"
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
        },
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

describe('eventBusPublicAccess', function () {
    describe('run', function () {
        it('should PASS if Event bus policy is not exposed to everyone', function (done) {
            const cache = createCache([listEventBuses[1]]);
            eventBusPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Event bus policy is exposed to everyone ', function (done) {
            const cache = createCache([listEventBuses[0]]);
            eventBusPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should PASS if Event bus does not use custom policy', function (done) {
            const cache = createCache([listEventBuses[2]]);
            eventBusPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Event Bus found', function (done) {
            const cache = createCache([]);
            eventBusPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list event bus', function (done) {
            const cache = createCache([],{ message: 'Unable to list event bus' });
            eventBusPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should not return anything if query to list event bus response not found', function (done) {
            const cache = createNullCache();
            eventBusPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
