var expect = require('chai').expect;
var automationAcctHasTags = require('./automationAcctHasTags.js');

const automationAccounts = [
    {
        "id": "/subscriptions/12345/resourceGroups/DefaultResourceGroup-EUS/providers/Microsoft.Automation/automationAccounts/Automate-12345-EUS2",
        "location": "EastUS2",
        "name": "Automate-12345-EUS2",
        "type": "Microsoft.Automation/AutomationAccounts",
        "tags": { "key": "value" },

    },
    {
        "id": "/subscriptions/12345/resourceGroups/DefaultResourceGroup-CUS/providers/Microsoft.Automation/automationAccounts/Automate-12345-CUS",
        "location": "centralus",
        "name": "Automate-12345-CUS",
        "type": "Microsoft.Automation/AutomationAccounts",
        "tags": {},
        "publicNetworkAccess": true,
    }
];

const createCache = (automationAccounts,err) => {
    return {
        automationAccounts: {
            list: {
                'eastus': {
                    data: automationAccounts,
                    err: err
                }
            }
        }
    }
};

describe('automationAcctHasTags', function () {
    describe('run', function () {

        it('should give pass result if No existing automation accounts found', function (done) {
            const cache = createCache([]);
            automationAcctHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Automation accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation accounts:', function (done) {
            const cache = createCache(null, 'Error');
            automationAcctHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Automation account has tags associated', function (done) {
            const cache = createCache([automationAccounts[0]]);
            automationAcctHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation account has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Automation account does not have tags associated', function (done) {
            const cache = createCache([automationAccounts[1]]);
            automationAcctHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automation account does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});