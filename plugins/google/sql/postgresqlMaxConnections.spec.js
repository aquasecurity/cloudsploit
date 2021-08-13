var expect = require('chai').expect;
var plugin = require('./postgresqlMaxConnections');

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

describe('postgresqlMaxConnections', function () {
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

            plugin.run(cache, { min_postgres_max_connections: '15' }, callback);
        });

        it('should give passing result if sql instance database type is not of PostgreSQL type', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL instance database version is not of PostgreSQL type');
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

            plugin.run(cache, { min_postgres_max_connections: '15' }, callback);
        });

        it('should give passing result if PostgreSQL instance max_connection value is is greater than or equal to desired value', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is greater than or equal to');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "POSTGRES_13",
                    settings: {
                      databaseFlags: [
                        {
                            name: "max_connections",
                            value: "15",
                        },
                      ]}
                }],
            );

            plugin.run(cache, { min_postgres_max_connections: '15' }, callback);
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

            plugin.run(cache, { min_postgres_max_connections: '20' }, callback);
        });

        it('should give failing result if PostgreSQL instance max_connection value is les than desired value', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is les than');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "POSTGRES_13",
                    settings: {
                      databaseFlags: [
                        {
                            name: "max_connections",
                            value: "15",
                        },
                      ]}
                }],
            );

            plugin.run(cache, { min_postgres_max_connections: '20' }, callback);
        });

        it('should give passing result if allow default max connections value setting is true and mex_connections flag value is not set', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('PostgreSQL instance does not have max_connections value set and is using default value');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "POSTGRES_13",
                    settings: {
                      databaseFlags: [
                    ]}
                }],
            );

            plugin.run(cache, { min_postgres_max_connections: '20', allow_default_max_connections_value: 'true' }, callback);
        });

        it('should give failing result if allow default max connections value setting is false and mex_connections flag value is not set', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('PostgreSQL instance does not have max_connections value set and is using default value');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [{
                    instanceType: "CLOUD_SQL_INSTANCE",
                    name: "testing-instance",
                    databaseVersion: "POSTGRES_13",
                    settings: {
                      databaseFlags: [
                    ]}
                }],
            );

            plugin.run(cache, { min_postgres_max_connections: '20', allow_default_max_connections_value: 'false' }, callback);
        });
    })
})