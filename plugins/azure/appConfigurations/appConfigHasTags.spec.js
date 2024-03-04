var expect = require('chai').expect;
var appConfigHasTags = require('./appConfigHasTags.js');

const appConfigurations = [
    {
        "type": "Microsoft.AppConfiguration/configurationStores",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "tags": { "key": "value" },
        "id": "/subscriptions/123/resourceGroups/meerab-rg/providers/Microsoft.AppConfiguration/configurationStores/meerab-test-rg",

    },
    {
        "type": "Microsoft.AppConfiguration/configurationStores",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/meerab-rg/providers/Microsoft.AppConfiguration/configurationStores/meerab-test-rg",

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

describe('appConfigHasTags', function () {
    describe('run', function () {

        it('should give pass result if No existing app configurations found', function (done) {
            const cache = createCache([]);
            appConfigHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing App Configurations found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query app configurations:', function (done) {
            const cache = createCache(null, 'Error');
            appConfigHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query App Configuration:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if App Configuration has tags associated', function (done) {
            const cache = createCache([appConfigurations[0]]);
            appConfigHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('App Configuration has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if App Configuration does not have tags associated', function (done) {
            const cache = createCache([appConfigurations[1]]);
            appConfigHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('App Configuration does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});