var expect = require('chai').expect;
var plugin = require('./storageAutoIncreaseEnabled');

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

describe('storageAutoIncreaseEnabled', function () {
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

        it('should give failing result if sql instance has storage auto increase disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL instance has automatic storage increase disabled');
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
                        storageAutoResizeLimit: '100',
                        storageAutoResize: false,
                    }
                }],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if SQL instance automatic storage increase limit is less than or equal to set limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is less than or equal');
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
                        storageAutoResizeLimit: '100',
                        storageAutoResize: true,
                    }
                }],
            );

            plugin.run(cache, { sql_storage_auto_increase_limit: '150'}, callback);
        });

        it('should give failing result if SQL instance automatic storage increase limit is greater than set limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is greater than');
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
                        storageAutoResizeLimit: '200',
                        storageAutoResize: true,
                    }
                }],
            );

            plugin.run(cache, { sql_storage_auto_increase_limit: '150'}, callback);
        });
    })
})