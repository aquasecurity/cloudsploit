var expect = require('chai').expect;
var plugin = require('./dbPubliclyAccessible');

const createCache = (err, data) => {
    return {
        instances: {
            sql: {
                list: {
                    'global': {
                        err: err,
                        data: data
                    }
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: [{ name: 'test-project' }]
                }
            }
        }
    }
};

describe('dbPubliclyAccessible', function () {
    describe('run', function () {
        it('should give unknown result if a sql instance error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query SQL instances');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                ['error'],
                null,
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no sql instances found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL instances found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no sql instances is publicly accessible', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Instance is not publicly accessible');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        name: 'testing-instance1',
                        instanceType: 'CLOUD_SQL_INSTANCE',
                        settings: {
                          tier: "db-custom-4-26624",
                          kind: "sql#settings",
                          ipConfiguration: {
                            privateNetwork:true,
                            authorizedNetworks: [
                            ],
                            ipv4Enabled: false,
                          },
                        },
                        ipAddresses: [
                          {
                            type: "PRIMARY",
                            ipAddress: "34.82.209.99",
                          },
                        ],
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if any sql instances is publicly accessible by all IP addresses', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL Instance is publicly accessible by all IP addresses');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        name: 'testing-instance1',
                        instanceType: 'CLOUD_SQL_INSTANCE',
                        settings: {
                          tier: "db-custom-4-26624",
                          kind: "sql#settings",
                          ipConfiguration: {
                            privateNetwork:false,
                            authorizedNetworks: [
                                {
                                    value: "0.0.0.0/0",
                                    name: "my",
                                    kind: "sql#aclEntry",
                                }
                            ],
                            ipv4Enabled: true,
                          },
                        },
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give warn result if any sql instances is publicly accessible by specific IP addresses', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(1);
                expect(results[0].message).to.include('SQL Instance is publicly accessible by specific IP addresses');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        name: 'testing-instance1',
                        instanceType: 'CLOUD_SQL_INSTANCE',
                        settings: {
                          tier: "db-custom-4-26624",
                          kind: "sql#settings",
                          ipConfiguration: {
                            privateNetwork:false,
                            authorizedNetworks: [
                                {
                                    value: "10.0.0.0/0",
                                    name: "my",
                                    kind: "sql#aclEntry",
                                }
                            ],
                            ipv4Enabled: true,
                          },
                        }
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
        it('should give passing result if sql instance is not publicly accessible', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL Instance is not publicly accessible');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                [
                    {
                        name: 'testing-instance1',
                        instanceType: 'CLOUD_SQL_INSTANCE',
                        settings: {
                          tier: "db-custom-4-26624",
                          kind: "sql#settings",
                          ipConfiguration: {
                            privateNetwork:false,
                            authorizedNetworks: [
                            ],
                            ipv4Enabled: true,
                          },
                        }
                    }
                ],
            );
            plugin.run(cache, {}, callback);
        });
    })
});