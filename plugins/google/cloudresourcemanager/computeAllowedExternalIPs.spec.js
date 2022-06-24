var expect = require('chai').expect;
var plugin = require('./computeAllowedExternalIPs');

const createCache = (err, data) => {
    return {
        organizations: {
            listOrgPolicies: {
                'global': {
                    err: err,
                    data: data
                }
            },
        },
    }
};

describe('computeAllowedExternalIPs', function () {
    describe('run', function () {

        it('should give unknow if an organization policies error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query organization policies');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                'error',
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no organization policies are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No organization policies found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if external IPs are not allowed for all VM instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is enforced');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "policies": [
                            {
                                "constraint": "constraints/compute.vmExternalIpAccess",
                                "updateTime": "2021-10-19T20:42:37.813762Z",
                                "listPolicy": {
                                    "allowedValues": [
                                        "projects/my-test-project/zones/us-central1-a/instances/instance-1"
                                    ]
                                }
                            },
                        ]
                    }
                      
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if external IPs are allowed for all VM instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is not enforced');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "policies": [
                            {
                                "constraint": "constraints/compute.vmExternalIpAccess",
                                "updateTime": "2021-10-19T20:42:37.813762Z",
                                "listPolicy": {
                                    "allValues": "ALLOW"
                                }
                            },
                        ]
                    }

                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
});