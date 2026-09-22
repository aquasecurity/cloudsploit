var expect = require('chai').expect;
var appInsightsConfigured = require('./appInsightsConfigured.js');

const components = [
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/microsoft.insights/components/test-insights",
        "name": "test-insights",
        "type": "microsoft.insights/components",
        "location": "eastus",
        "kind": "web",
        "applicationId": "test-insights",
        "provisioningState": "Succeeded"
    }
];

const createCache = (insights, err) => {
    return {
        appInsights: {
            list: {
                'global': {
                    data: insights,
                    err: err
                }
            }
        }
    };
};

describe('appInsightsConfigured', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for application insights', function (done) {
            const cache = createCache(null, ['error']);
            appInsightsConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Application Insights');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if application insights is not configured', function (done) {
            const cache = createCache([], null);
            appInsightsConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Application Insights is not configured for the subscription');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if application insights is configured', function (done) {
            const cache = createCache(components, null);
            appInsightsConfigured.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Application Insights is configured for the subscription');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
