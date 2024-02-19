var expect = require('chai').expect;
var accountCMKEncrypted = require('./accountCMKEncrypted');

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

describe('accountCMKEncrypted', function() {
    describe('run', function() {
        it('should give passing result if no openai accounts', function(done) {
            const cache = createCache([]);
            accountCMKEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing OpenAI accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for openai accounts', function(done) {
            const cache = createErrorCache();
            accountCMKEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query OpenAI accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give passing result if openai account is encrypted using CMK', function(done) {
            const cache = createCache([accounts[0]]);
            accountCMKEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('OpenAI Account is encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if openai account is not encrypted using CMK', function(done) {
            const cache = createCache([accounts[1]]);
            accountCMKEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('OpenAI Account is not encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
});