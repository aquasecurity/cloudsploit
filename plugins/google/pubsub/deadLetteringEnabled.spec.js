var expect = require('chai').expect;
var plugin = require('./deadLetteringEnabled');

const subscriptions = [
    {
        name: 'projects/my-test-project/subscriptions/sub-1',
        topic: 'projects/my-test-project/topics/topic-1',
        pushConfig: {},
        ackDeadlineSeconds: 10,
        messageRetentionDuration: '604800s',
        expirationPolicy: { ttl: '2678400s' }
    },
    {
        name: 'projects/my-test-project/subscriptions/sub-1',
        topic: 'projects/my-test-project/topics/topic-1',
        pushConfig: {},
        ackDeadlineSeconds: 10,
        messageRetentionDuration: '604800s',
        expirationPolicy: { ttl: '2678400s' },
        deadLetterPolicy: {
          deadLetterTopic: 'projects/my-test-project/topics/topic-1',
          maxDeliveryAttempts: 5
        }
      }

];

const createCache = (listSubscriptions, errSubscriptions) => {
    return {
        subscriptions: {
            list: {
                'global': {
                    err: errSubscriptions,
                    data: listSubscriptions
                }
            }
        }
    }
};

describe('deadLetteringEnabled', function () {
    describe('run', function () {
        it('should give passing result if no Pub/Sub subscriptions found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Pub/Sub subscriptions found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Pub/Sub subscription has dead lettering enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('has dead lettering enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [subscriptions[1]],
                null            
                );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if Pub/Sub subscription does not have dead lettering enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have dead lettering enabled');
                expect(results[0].region).to.equal('global');
                done();
            };

            const cache = createCache(
                [subscriptions[0]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for Pub/Sub subscriptions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Pub/Sub subscriptions');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                {message: 'error'},
            );

            plugin.run(cache, {}, callback);
        });
    })
});

