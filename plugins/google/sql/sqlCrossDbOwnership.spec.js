var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./sqlCrossDbOwnership');

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
        }
    }
};

describe('sqlCrossDbOwnership', function () {
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

        it('should give passing result if sql instance database type is not of SQL Server type', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL instance database type is not of SQL Server type');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    name: "testing-instance",
                    databaseVersion: "MYSQL_5_7",
                }],
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if SQL instance has cross DB ownership chaining flag disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL instance has cross DB ownership chaining flag disabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "SQLSERVER_13",
                    settings: {
                      databaseFlags: [
                        {
                            name: "cross db ownership chaining",
                            value: "off",
                        },
                      ]}
                }],
            );
            
            plugin.run(cache, {}, callback);
        });
        it('should give failing result if sql instances has cross DB ownership chaining flag enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL instance has cross DB ownership chaining flag enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "SQLSERVER_13",
                    settings: {
                      databaseFlags: [
                        {
                            name: "cross db ownership chaining",
                            value: "on",
                        },
                      ]}
                }],
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if sql instances has cross DB ownership chaining flag enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL instance has cross DB ownership chaining flag enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "SQLSERVER_13",
                    settings: {
                      databaseFlags: [
                        {
                            name: "log_checkpoints",
                            value: "on",
                        },
                      ]}
                }],
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if sql instances does not have any flags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL instance does not have any flags');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "SQLSERVER_13",
                    settings: {
                      databaseFlags: []
                    }
                }],
            );

            plugin.run(cache, {}, callback);
        });
    })
})