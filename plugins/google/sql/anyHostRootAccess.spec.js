var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./anyHostRootAccess');

const createCache = (err, data) => {
    return {
        users: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('anyHostRootAccess', function () {
    describe('run', function () {
        it('should give passing result if no users are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL users found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no root user is found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No root user found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "sql#user",
                        "etag": "7a07134ea59e53658f3526028630dbfd9c14c3db7140eaedde83ae7418898a19",
                        "name": "mysql.sys",
                        "host": "localhost",
                        "instance": "mysqltest1",
                        "project": "frost-forest-281330"
                    },
                ],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if the root user does not have access to the instance from any host', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The root user does not have access to the instance from any host');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "sql#user",
                        "etag": "7a07134ea59e53658f3526028630dbfd9c14c3db7140eaedde83ae7418898a19",
                        "name": "mysql.sys",
                        "host": "localhost",
                        "instance": "mysqltest1",
                        "project": "frost-forest-281330"
                    },
                    {
                        "kind": "sql#user",
                        "etag": "18e4b9125675f6570ad430df7240e6226e0e50b8a40ea521b90827c80d10d8ab",
                        "name": "root",
                        "host": "192.192.0.0/32",
                        "instance": "mysqltest1",
                        "project": "frost-forest-281330"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if the root user has access to the instance from any host', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The root user has access to the instance from any host');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "sql#user",
                        "etag": "7a07134ea59e53658f3526028630dbfd9c14c3db7140eaedde83ae7418898a19",
                        "name": "mysql.sys",
                        "host": "localhost",
                        "instance": "mysqltest1",
                        "project": "frost-forest-281330"
                    },
                    {
                        "kind": "sql#user",
                        "etag": "18e4b9125675f6570ad430df7240e6226e0e50b8a40ea521b90827c80d10d8ab",
                        "name": "root",
                        "host": "%",
                        "instance": "mysqltest1",
                        "project": "frost-forest-281330"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
});