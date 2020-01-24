var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./clbSecurityPolicyEnabled');

const createCache = (err, data) => {
    return {
        backendServices: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('clbSecurityPolicyEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a backend service error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query backend services');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no backend services are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No load balancers found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Security Policy is Attached to a backend service', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The backend service has an attached security policy');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "4157315546279923160",
                        "creationTimestamp": "2019-10-02T11:57:59.879-07:00",
                        "name": "giotestlb1",
                        "description": "",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/global/backendServices/giotestlb1",
                        "healthChecks": [
                            "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/global/healthChecks/giohealthcheck1"
                        ],
                        "timeoutSec": 30,
                        "port": 80,
                        "protocol": "HTTPS",
                        "fingerprint": "MWDwvqlcr5k=",
                        "portName": "https",
                        "enableCDN": false,
                        "sessionAffinity": "NONE",
                        "affinityCookieTtlSec": 0,
                        "loadBalancingScheme": "EXTERNAL",
                        "connectionDraining": {
                            "drainingTimeoutSec": 300
                        },
                        "securityPolicy": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/global/securityPolicies/giosecuritypolicy1",
                        "kind": "compute#backendService"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Security Policy is not Attached to a backend service', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The backend service does not have an attached security policy');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "4157315546279923160",
                        "creationTimestamp": "2019-10-02T11:57:59.879-07:00",
                        "name": "giotestlb1",
                        "description": "",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/global/backendServices/giotestlb1",
                        "healthChecks": [
                            "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/global/healthChecks/giohealthcheck1"
                        ],
                        "timeoutSec": 30,
                        "port": 80,
                        "protocol": "HTTPS",
                        "fingerprint": "MWDwvqlcr5k=",
                        "portName": "https",
                        "enableCDN": false,
                        "sessionAffinity": "NONE",
                        "affinityCookieTtlSec": 0,
                        "loadBalancingScheme": "EXTERNAL",
                        "connectionDraining": {
                            "drainingTimeoutSec": 300
                        },
                        "kind": "compute#backendService"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
});