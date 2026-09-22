var expect = require('chai').expect;
var subscriptionTenantPolicy = require('./subscriptionTenantPolicy.js');

const policies = [
    {
        "id": "providers/Microsoft.Subscription/policies/default",
        "name": "default",
        "type": "providers/Microsoft.Subscription/policies",
        "policyId": "d207c7bd-fcb1-4dd3-855a-cfd2f9b651e8",
        "blockSubscriptionsLeavingTenant": true,
        "blockSubscriptionsIntoTenant": true,
        "exemptedPrincipals": []
    },
    {
        "id": "providers/Microsoft.Subscription/policies/default",
        "name": "default",
        "type": "providers/Microsoft.Subscription/policies",
        "policyId": "d207c7bd-fcb1-4dd3-855a-cfd2f9b651e8",
        "blockSubscriptionsLeavingTenant": true,
        "blockSubscriptionsIntoTenant": false,
        "exemptedPrincipals": []
    },
    {
        "id": "providers/Microsoft.Subscription/policies/default",
        "name": "default",
        "type": "providers/Microsoft.Subscription/policies",
        "policyId": "d207c7bd-fcb1-4dd3-855a-cfd2f9b651e8",
        "blockSubscriptionsLeavingTenant": false,
        "blockSubscriptionsIntoTenant": false,
        "exemptedPrincipals": []
    }
];

const createCache = (policy, err) => {
    return {
        subscriptionPolicies: {
            get: {
                'global': {
                    data: policy,
                    err: err
                }
            }
        }
    };
};

describe('subscriptionTenantPolicy', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for subscription tenant policy', function (done) {
            const cache = createCache(null, ['error']);
            subscriptionTenantPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for subscription tenant policy');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if no subscription tenant policy found', function (done) {
            const cache = createCache([], null);
            subscriptionTenantPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing subscription tenant policy found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if subscriptions cannot be moved into or out of the tenant', function (done) {
            const cache = createCache([policies[0]], null);
            subscriptionTenantPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Subscriptions cannot be moved into or out of the tenant');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if subscriptions can be moved into the tenant', function (done) {
            const cache = createCache([policies[1]], null);
            subscriptionTenantPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Subscriptions can be moved into or out of the tenant');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if subscriptions can be moved into and out of the tenant', function (done) {
            const cache = createCache([policies[2]], null);
            subscriptionTenantPolicy.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Subscriptions can be moved into or out of the tenant');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
