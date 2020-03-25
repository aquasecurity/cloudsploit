var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./statelessSecurityRules');

const createCache = (err, data, sdata, serr) => {
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

        securityList: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
        securityRule: {
            list: {
                'us-ashburn-1': {
                    err: serr,
                    data: sdata
                }
            }
        }
    }
};

describe('statelessSecurityRules', function () {
    describe('run', function () {
        it('should give unknown result if an security list error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for security lists')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null,
                null,
                null
            );

            plugin.run(cache, {}, callback);
        });
        it('should give unknown result if an security rule error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for security rules')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                [],
                [],
                null,
                ['error']
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no security list records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[1].status).to.equal(0)
                expect(results[1].message).to.include('No security lists found')
                expect(results[1].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
                [{hello:'world'}, {how:'are you'}],
                null

            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no security rule records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No security rules found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [{hello:'world'}, {how:'are you'}],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no security list or security rule records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No security rules or lists found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if all security lists security rules are stateless', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[1].status).to.equal(0)
                expect(results[1].message).to.include('All security lists have stateless security')
                expect(results[1].region).to.equal('us-ashburn-1')
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
                        "timeExpires": "2019-10-05T22:10:42.491Z"
                    }
                ],
                ['helloWorld'],
                null
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if all network security groups security rules are stateless', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[1].status).to.equal(0)
                expect(results[1].message).to.include('All network security groups have stateless security rules')
                expect(results[1].region).to.equal('us-ashburn-1')
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
                        "timeExpires": "2019-10-05T22:10:42.491Z",
                        "ingressSecurityRules": ['hello']
                    }
                ],
                [{isStateless: true}],
                null

            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if all security list and network security groups security rules are stateless', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('All network security groups and security lists have stateless security rules')
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
                        "timeExpires": "2019-10-05T22:10:42.491Z"
                    }
                ],
                [{isStateless: true}]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if security list security rules are stateful', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('The security list has')
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
                        "timeExpires": "2019-10-05T22:10:42.491Z",
                        "ingressSecurityRules": ['hello']
                    }
                ],
                [{isStateless: true}],
                null
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if network security groups security rules are not stateless', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('has stateful security rules')
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
                        "timeExpires": "2019-10-05T22:10:42.491Z",
                    }
                ],
                [{isStateless: false}],
                null
            );

            plugin.run(cache, {}, callback);
        });

    })
})