var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./inboundSecurityLists');

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

        securityList: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('inboundSecurityLists', function () {
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
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no security lists records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No security lists found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        });
       
        it('should give passing result if security list has ingress rules configured', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Security list has ingress rules')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "list2",
                        "displayName": "list-2",
                        "timeCreated": "2019-07-29T22:10:50.075Z",
                        "ingressSecurityRules": [{
                            "isStateless": false,
                            "protocol": '6',
                            "source": '0.0.0.0/0',
                            "sourceType": 'CIDR_BLOCK',
                          }],
                        "lifecycleState": "AVAILABLE",
                        "vcnId": "v1"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if security list does not have ingress rules configured', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Security list does not have ingress rules')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "list2",
                        "displayName": "list-2",
                        "timeCreated": "2019-07-29T22:10:50.075Z",
                        "ingressSecurityRules": [],
                        "lifecycleState": "AVAILABLE",
                        "vcnId": "v1"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
    })
})