var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./serverCertificateRotation');

var passDate = new Date();
passDate.setMonth(passDate.getMonth() + 7);
var failDate = new Date();
failDate.setMonth(failDate.getMonth() + 1);

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

describe('serverCertificateExpiry', function () {
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

        it('should give passing result if no sql instances are found', function (done) {
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

        it('should give passing result if SQL instance SSL certificate will expire after more than threshold expiry days', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL instance SSL certificate will expire after');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "POSTGRES_13",
                    serverCaCert: {
                        expirationTime: passDate
                    }
                }],
            );

            plugin.run(cache, { server_certicate_expiration_threshold: '50' }, callback);
        });

        it('should give failing result if SQL instance SSL certificate will expire less than threshold expiry days', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL instance SSL certificate will expire after');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "POSTGRES_13",
                    serverCaCert: {
                        expirationTime: failDate
                    }
                }],
            );

            plugin.run(cache, { server_certicate_expiration_threshold: '50' }, callback);
        });
        
    })
})