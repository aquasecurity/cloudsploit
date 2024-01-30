var expect = require('chai').expect;
var logAnalyticsWorkspacePublic = require('./logAnalyticsWorkspacePublic');

const workSpaces = [
    {
        "id": "/subscriptions/01234567/resourcegroups/6685/providers/microsoft.operationalinsights/workspaces/test2",
        "name": "test2",
        "type": "Microsoft.OperationalInsights/workspaces",
        "location": "eastus",
        "publicNetworkAccessForQuery": "Enabled",
        "publicNetworkAccessForIngestion": "Enabled"
    },
    {
        "id": "/subscriptions/01234567/resourcegroups/6685/providers/microsoft.operationalinsights/workspaces/test",
        "name": "test",
        "type": "Microsoft.OperationalInsights/workspaces",
        "location": "eastus",
        "publicNetworkAccessForQuery": "Disabled",
        "publicNetworkAccessForIngestion": "Disabled"
    }
];

const createCache = (logAnalytics) => {
    let workspace = {};
    if (logAnalytics) {
        workspace['data'] = logAnalytics;
    }
    return {
        logAnalytics: {
            listWorkspaces: {
                'eastus': workspace
            }
        }
    };
};

describe('logAnalyticsWorkspacePublic', function() {
    describe('run', function() {
        it('should give passing result if No existing Log Analytics Workspaces found', function(done) {
            const cache = createCache([]);
            logAnalyticsWorkspacePublic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Log Analytics Workspaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Log Analytics Workspaces', function(done) {
            const cache = createCache();
            logAnalyticsWorkspacePublic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Log Analytics Workspaces: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Log Analytics Workspace is not Public', function(done) {
            const cache = createCache([workSpaces[1]]);
            logAnalyticsWorkspacePublic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Log Analytics Workspace is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Log Analytics Workspace is Public', function(done) {
            const cache = createCache([workSpaces[0]]);
            logAnalyticsWorkspacePublic.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Log Analytics Workspace is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
