
var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./preAuthRequestsExpiry');

const createCache = (err, data) => {
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

        preAuthenticatedRequest: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('preAuthRequestsExpiry', function () {
    describe('run', function () {
        it('should give unknown result if an requests error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for pre-authenticated requests')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if no requests records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No pre-authenticated requests found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if there are no active preauthenticated requests', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No active pre-authenticated requests')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "G7h3izMy2eouVoMISHnOIq5q2rJXZvvDbrj7/t2P3iM=:Screen Shot 2019-07-24 at 5.12.12 PM.png",
                        "name": "par-object-20190729-1710",
                        "accessType": "ObjectRead",
                        "objectName": "Screen Shot 2019-07-24 at 5.12.12 PM.png",
                        "timeCreated": "2019-07-29T22:10:50.075Z",
                        "timeExpires": "2019-08-05T22:10:42.491Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give passing result if all preauthenticated requests have short expiration', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('All pre-authenticated requests are set to expire in less than')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };
            var firstDay = new Date();
            var nextWeek = new Date(firstDay.getTime() + 7 * 24 * 60 * 60 * 1000);
            nextWeek = nextWeek.toISOString()
            firstDay = firstDay.toISOString()
            const cache = createCache(
                null,
                [
                    {
                        "id": "G7h3izMy2eouVoMISHnOIq5q2rJXZvvDbrj7/t2P3iM=:Screen Shot 2019-07-24 at 5.12.12 PM.png",
                        "name": "par-object-20190729-1710",
                        "accessType": "ObjectRead",
                        "objectName": "Screen Shot 2019-07-24 at 5.12.12 PM.png",
                        "timeCreated": firstDay,
                        "timeExpires": nextWeek
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give warning result if preauthenticated requests have an expiration date longer than intended', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(1)
                expect(results[0].message).to.include('pre-authenticated request expires in')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };
            var firstDay = new Date();
            var nextWeek = new Date(firstDay.getTime() + 14 * 24 * 60 * 60 * 1000);
            nextWeek = nextWeek.toISOString()
            firstDay = firstDay.toISOString()
            const cache = createCache(
                null,
                [
                    {
                        "id": "G7h3izMy2eouVoMISHnOIq5q2rJXZvvDbrj7/t2P3iM=:Screen Shot 2019-07-24 at 5.12.12 PM.png",
                        "name": "par-object-20190729-1710",
                        "accessType": "ObjectReadWrite",
                        "objectName": "Screen Shot 2019-07-24 at 5.12.12 PM.png",
                        "timeCreated": firstDay,
                        "timeExpires": nextWeek
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if preauthenticated requests ave an expiration date way longer than intended', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('pre-authenticated request expires in')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "G7h3izMy2eouVoMISHnOIq5q2rJXZvvDbrj7/t2P3iM=:Screen Shot 2019-07-24 at 5.12.12 PM.png",
                        "name": "par-object-20190729-1710",
                        "accessType": "AnyObjectWrite",
                        "objectName": "Screen Shot 2019-07-24 at 5.12.12 PM.png",
                        "timeCreated": "2019-07-29T22:10:50.075Z",
                        "timeExpires": "2029-11-05T22:10:42.491Z"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})