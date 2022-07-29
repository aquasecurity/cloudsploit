var expect = require('chai').expect;
var plugin = require('./skipDefaultNetworkCreation');

const createCache = (err, data) => {
    return {
        organizations: {
            list: {
                'global': {
                    data: [
                        {
                            "organizationId": "123456",
                            "displayName": "myorg",
                            "creationTime": "2018-03-03T17:56:10.122Z",
                            "lifecycleState": "ACTIVE",
                            "name": "organizations/123456"
                        }
                    ],
                    err: null
                }
            },
            listOrgPolicies: {
                'global': {
                    err: err,
                    data: data
                }
            },
        },
    }
};

describe('skipDefaultNetworkCreation', function () {
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

        it('should give passing result if skip default network creation is enabled', function (done) {
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
                                "constraint": "constraints/compute.skipDefaultNetworkCreation",
                                "updateTime": "2021-10-19T20:42:37.813762Z",
                                "booleanPolicy": {
                                    "enforced": true
                                }
                            },
                        ]
                    }
                      
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if skip default network creation is disabled', function (done) {
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
                                "constraint": "constraints/compute.skipDefaultNetworkCreation",
                                "updateTime": "2021-10-19T20:42:37.813762Z",
                                "booleanPolicy": {}
                            },
                        ]
                    }

                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
});