var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./logConnectionsEnabled');

const createCache = (err, data) => {
    return {
        configurations: {
            listByServer: {
                'eastus': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('logConnectionsEnabled', function () {
    describe('run', function () {
        it('should give passing result if no servers', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL Servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        })

        it('should give failing result if postgresql server has log_connections disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Connection logs are disabled for the PostgreSQL Server configuration');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.DBforPostgreSQL/servers/gioservertest1/configurations/log_checkpoints",
                        "name": "log_connections",
                        "type": "Microsoft.DBforPostgreSQL/servers/configurations",
                        "value": "off",
                        "description": "Logs each checkpoint.",
                        "defaultValue": "on",
                        "dataType": "Boolean",
                        "allowedValues": "on,off",
                        "source": "system-default",
                        "location": "ukwest",
                        "storageAccount": {
                            "name": "gioservertest1"
                        }
                    },
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if postgresql server has log_connections enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Connection logs are enabled for the PostgreSQL Server configuration');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.DBforPostgreSQL/servers/gioservertest1/configurations/log_checkpoints",
                        "name": "log_connections",
                        "type": "Microsoft.DBforPostgreSQL/servers/configurations",
                        "value": "on",
                        "description": "Logs each checkpoint.",
                        "defaultValue": "on",
                        "dataType": "Boolean",
                        "allowedValues": "on,off",
                        "source": "system-default",
                        "location": "ukwest",
                        "storageAccount": {
                            "name": "gioservertest1"
                        }
                    },
                ]
            );

            auth.run(cache, {}, callback);
        });
    })
})