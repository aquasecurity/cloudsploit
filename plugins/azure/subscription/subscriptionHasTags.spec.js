var expect = require('chai').expect;
var subscriptionHasTags = require('./subscriptionHasTags');

const subscription = [
    {
        'name': 'test-sub',
        'id': '/subscriptions/123',
        'tags': { 'key': 'value'},
        'subscriptionId': '123',
    },
    {
        'name': 'test-sub',
        'id': '/subscriptions/123',
        'subscriptionId': '123',
    }
];

const createCache = (subscription) => {
    return {
        subscriptions: {
            get: {
                'global': {
                    data: subscription
                } 
                    
            },
        }
    };
};

describe('subscriptionHasTags', function() {
    describe('run', function() {

        it('should give unknown result if unable to query for subscription', function(done) {
            const cache = createCache(null);
            subscriptionHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for subscriptions');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if subscription has tags', function(done) {
            const cache = createCache([subscription[0]]);
            subscriptionHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Subscription has tags');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if subscription does not have tags', function(done) {
            const cache = createCache([subscription[1]]);
            subscriptionHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Subscription does not have tags');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});