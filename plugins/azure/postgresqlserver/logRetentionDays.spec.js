var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./logRetentionDays');

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

describe('logRetentionDays', function () {
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

        it('should give failing result if postgresql server has log_retention_days less than 4 days', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Log retention period is 3 days or less');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.DBforPostgreSQL/servers/gioservertest1/configurations/log_checkpoints",
                        "name": "log_retention_days",
                        "type": "Microsoft.DBforPostgreSQL/servers/configurations",
                        "value": "2",
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

        it('should give passing result if postgresql server has log_retention_days more than 3 days', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Log retention period is greater than 3 days');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/Default-ActivityLogAlerts/providers/Microsoft.DBforPostgreSQL/servers/gioservertest1/configurations/log_checkpoints",
                        "name": "log_retention_days",
                        "type": "Microsoft.DBforPostgreSQL/servers/configurations",
                        "value": "4",
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