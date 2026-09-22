var expect = require('chai').expect;
var serviceHealthAlertEnabled = require('./serviceHealthAlertEnabled.js');

const activityLogAlerts = [
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/microsoft.insights/activityLogAlerts/ServiceHealthAlert",
        "name": "ServiceHealthAlert",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "scopes": ["/subscriptions/123"],
        "condition": {
            "allOf": [
                { "field": "category", "equals": "ServiceHealth" }
            ]
        },
        "enabled": true
    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/microsoft.insights/activityLogAlerts/AdministrativeAlert",
        "name": "AdministrativeAlert",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "scopes": ["/subscriptions/123"],
        "condition": {
            "allOf": [
                { "field": "category", "equals": "Administrative" },
                { "field": "Status", "equals": "Succeeded" }
            ]
        },
        "enabled": true
    },
    {
        "id": "/subscriptions/123/resourceGroups/test/providers/microsoft.insights/activityLogAlerts/DisabledServiceHealthAlert",
        "name": "DisabledServiceHealthAlert",
        "type": "Microsoft.Insights/ActivityLogAlerts",
        "location": "global",
        "scopes": ["/subscriptions/123"],
        "condition": {
            "allOf": [
                { "field": "category", "equals": "ServiceHealth" }
            ]
        },
        "enabled": false
    }
];

const createCache = (alerts, err) => {
    return {
        activityLogAlerts: {
            listBySubscriptionId: {
                'global': {
                    data: alerts,
                    err: err
                }
            }
        }
    };
};

describe('serviceHealthAlertEnabled', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for activity alerts', function (done) {
            const cache = createCache(null, ['error']);
            serviceHealthAlertEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Activity Alerts');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if no existing activity alerts found', function (done) {
            const cache = createCache([], null);
            serviceHealthAlertEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Activity Alerts found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if a Service Health alert is enabled', function (done) {
            const cache = createCache([activityLogAlerts[0]], null);
            serviceHealthAlertEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Log Alert for Service Health is enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if no Service Health alert exists', function (done) {
            const cache = createCache([activityLogAlerts[1]], null);
            serviceHealthAlertEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Log Alert for Service Health is not enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if the Service Health alert is disabled', function (done) {
            const cache = createCache([activityLogAlerts[2]], null);
            serviceHealthAlertEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Log Alert for Service Health is not enabled');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
