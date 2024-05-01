var expect = require('chai').expect;
var appConfigAccessKeyAuthDisabled = require('./appConfigAccessKeyAuthDisabled.js');

const appConfigurations = [
    {
        "type": "Microsoft.AppConfiguration/configurationStores",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "tags": { "key": "value" },
        "id": "/subscriptions/123/resourceGroups/meerab-rg/providers/Microsoft.AppConfiguration/configurationStores/meerab-test-rg",
        "disableLocalAuth": false,

    },
    {
        "type": "Microsoft.AppConfiguration/configurationStores",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/meerab-rg/providers/Microsoft.AppConfiguration/configurationStores/meerab-test-rg",
        "disableLocalAuth": true,

    }
];

const createCache = (appConfigurations,err) => {
    return {
        appConfigurations: {
            list: {
                'eastus': {
                    data: appConfigurations,
                    err: err
                }
            }
        }
    }
};

describe('appConfigAccessKeyAuthDisabled', function () {
    describe('run', function () {

        it('should give pass result if No existing app configurations found', function (done) {
            const cache = createCache([]);
            appConfigAccessKeyAuthDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Configurations found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query app configurations:', function (done) {
            const cache = createCache(null, 'Error');
            appConfigAccessKeyAuthDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Configuration:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if App Configuration has access key authentication disabled', function (done) {
            const cache = createCache([appConfigurations[1]]);
            appConfigAccessKeyAuthDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Configuration has access key authentication disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if App Configuration does not have access key authentication disabled', function (done) {
            const cache = createCache([appConfigurations[0]]);
            appConfigAccessKeyAuthDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Configuration does not have access key authentication disabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});