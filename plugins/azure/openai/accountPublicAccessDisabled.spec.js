var expect = require('chai').expect;
var accountPublicAccessDisabled = require('./accountPublicAccessDisabled');

const accounts = [
    {
        "id": "/subscriptions/12424/resourceGroups/bvttest/providers/Microsoft.CognitiveServices/accounts/acc1",
        "name": "acc1",
        "type": "Microsoft.CognitiveServices/accounts",
        "location": "eastus",
        "properties": {
            "publicNetworkAccess": 'Disabled'
        }
      },
      {
        "id": "/subscriptions/12424/resourceGroups/bvttest/providers/Microsoft.CognitiveServices/accounts/acc2",
        "name": "acc2",
        "type": "Microsoft.CognitiveServices/accounts",
        "location": "eastus",
        "properties": {
            "publicNetworkAccess": 'Enabled'
        }
      },
    
   
];

const createCache = (accounts) => {
    return {
        openAI: {
            listAccounts: {
                'eastus': {
                    data: accounts
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        openAI: {
            listAccounts: {
                'eastus': {}
            }
        }
    };
};

describe('accountPublicAccessDisabled', function() {
    describe('run', function() {
        it('should give passing result if no openai accounts', function(done) {
            const cache = createCache([]);
            accountPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing OpenAI accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for openai accounts', function(done) {
            const cache = createErrorCache();
            accountPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query OpenAI accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if openai account is not publicly accessible', function(done) {
            const cache = createCache([accounts[0]]);
            accountPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OpenAI Account is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if openai account is publicly accessible', function(done) {
            const cache = createCache([accounts[1]]);
            accountPublicAccessDisabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OpenAI Account is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});