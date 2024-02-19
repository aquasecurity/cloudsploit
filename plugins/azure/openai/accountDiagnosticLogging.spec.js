var expect = require('chai').expect;
var accountDiagnosticLogging = require('./accountDiagnosticLogging');

const accounts = [
    {
        "id": "/subscriptions/12424/resourceGroups/bvttest/providers/Microsoft.CognitiveServices/accounts/acc1",
        "name": "acc1",
        "type": "Microsoft.CognitiveServices/accounts",
        "location": "eastus",
        "properties": {
            "encryption": {
                'keySource': 'Microsoft.Keyvault'
            }
        }
      },
      {
        "id": "/subscriptions/12424/resourceGroups/bvttest/providers/Microsoft.CognitiveServices/accounts/acc2",
        "name": "acc2",
        "type": "Microsoft.CognitiveServices/accounts",
        "location": "eastus"
      },
    
   
];

const diagnosticSettings = [
    {
        id: 'subscriptions/12424/resourceGroups/bvttest/providers/Microsoft.CognitiveServices/accounts/acc1/providers/microsoft.insights/diagnosticSettings/test-setting',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'openai-setting',
        location: 'eastus',
        kind: null,
        tags: null,
        eventHubName: null,
        metrics: [],
        logs: [
            {
              "category": null,
              "categoryGroup": "allLogs",
              "enabled": true,
              "retentionPolicy": {
                "enabled": false,
                "days": 0
              }
            },
            {
              "category": null,
              "categoryGroup": "audit",
              "enabled": false,
              "retentionPolicy": {
                "enabled": false,
                "days": 0
              }
            }
          ],
        logAnalyticsDestinationType: null
    }
];

const createCache = (accounts, ds) => {
    const id = accounts && accounts.length ? accounts[0].id : null;
    return {
        openAI: {
            listAccounts: {
                'eastus': {
                    data: accounts
                }
            }
        },
        diagnosticSettings: {
            listByOpenAIAccounts: {
                'eastus': { 
                    [id]: { 
                        data: ds 
                    }
                }
            }

        },
    };
};

describe('accountDiagnosticLogging', function() {
    describe('run', function() {
        it('should give passing result if no openai accounts', function (done) {
            const cache = createCache([], null);
            accountDiagnosticLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing OpenAI accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for openai accounts', function (done) {
            const cache = createCache(null, ['error']);
            accountDiagnosticLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query OpenAI accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([accounts[0]], null);
            accountDiagnosticLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for account diagnostic settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if diagnostic logs enabled', function(done) {
            const cache = createCache([accounts[0]], [diagnosticSettings[0]]);
            accountDiagnosticLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OpenAI account has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if diagnostic logs not enabled', function(done) {
            const cache = createCache([accounts[0]], [[]]);
            accountDiagnosticLogging.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OpenAI account does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
