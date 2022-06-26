var expect = require('chai').expect;
var plugin = require('./notificationTopicSubscription');

const topics = [{
    name: 'topic-1',
    topicId: 'topic-1',
    shortTopicId: null,
    compartmentId: 'compartment-1',
    lifecycleState: 'ACTIVE',
    description: null,
    timeCreated: '2022-06-26T00:56:58.950Z',
  },
  {
    name: 'topic-2',
    topicId: 'topic-1',
    shortTopicId: null,
    compartmentId: 'compartment-1',
    lifecycleState: 'DELETED',
    description: null,
    timeCreated: '2022-06-26T00:56:58.950Z',
  }
];
const subscriptions = [
    {
        id: 'sub-1',
        topicId: 'topic-1',
        protocol: 'EMAIL',
        endpoint: 'myemail@gmail.com',
        lifecycleState: 'PENDING',
        compartmentId: 'compartment-1',
        createdTime: 1656205041117,
      },
      {
        id: 'sub-2',
        topicId: 'topic-1',
        protocol: 'EMAIL',
        endpoint: 'myemail@gmail.com',
        lifecycleState: 'ACTIVE',
        compartmentId: 'compartment-1',
        createdTime: 1656205041117,
      }
];

const createCache = (err, subscriptions, topicsErr, topics) => {
    return {
        regionSubscription: {
            "list": {
                "us-ashburn-1": {
                    "data": [
                        {
                            "regionKey": "IAD",
                            "regionName": "us-ashburn-1",
                            "status": "READY",
                            "isHomeRegion": true
                        },
                        {
                            "regionKey": "LHR",
                            "regionName": "uk-london-1",
                            "status": "READY",
                            "isHomeRegion": false
                        },
                        {
                            "regionKey": "PHX",
                            "regionName": "us-phoenix-1",
                            "status": "READY",
                            "isHomeRegion": false
                        }
                    ]
                }
            }
        },
        subscriptions: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: subscriptions
                }
            }
        },
        topics: {
            list: {
                'us-ashburn-1': {
                    err: topicsErr,
                    data: topics
                }
            }
        }
    }
};

describe('notificationTopicSubscription', function () {
    describe('run', function () {
        it('should give unknown result if unable to query for topics', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for topics')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                null,
                ['err'],
                undefined
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if no topics found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('No topics found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                null,
                null, 
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if no active topics found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('No active topics found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                null,
                null, 
                [topics[1]]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give unknown result if unable to query for subscriptions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for subscriptions')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['err'],
                undefined,
                null,
                topics
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if no subscriptions found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('No subscriptions found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
                null, 
                topics
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if no active subscriptions found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('No notification topics with active subscriptions found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [subscriptions[0]],
                null, 
                topics
            );

            plugin.run(cache, {}, callback);
        })


        it('should give passing result if there is one topic with active subscription', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('There is at least one')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [subscriptions[1]],
                null, 
                topics
            );

            plugin.run(cache, {}, callback);
        })


    });
});