var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./blockPolicyProtection');

const createCache = (err, data) => {
    return {
        regionSubscription: {
            "list": {
                "us-ashburn-1": {
                    "data": [
                        {
                            "regionKey": "IAD",
                            "regionName": "us-ashburn-1",
                            "status": "READY",
                            "isHomeRegion": true
                        },
                        {
                            "regionKey": "LHR",
                            "regionName": "uk-london-1",
                            "status": "READY",
                            "isHomeRegion": false
                        },
                        {
                            "regionKey": "PHX",
                            "regionName": "us-phoenix-1",
                            "status": "READY",
                            "isHomeRegion": false
                        }
                    ]
                }
            }
        },
        policy: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('blockPolicyProtection', function () {
    describe('run', function () {
        it('should give unknown result if a policy error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for policies:')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['hello'],
                undefined
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no policy records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No policies found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if a policy does not have block storage deletion protection', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('has the ability to delete')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "statements": [
                            "ALLOW GROUP Developers to manage all-resources IN TENANCY",
                            "Allow group Developers to manage file-systems in tenancy where request.permission!='FILE_SYSTEM_DELETE'",
                            "ALLOW GROUP ADMINISTRATORS to manage all-resources IN TENANCY"
                        ],
                        "id": "ocid1.policy.oc1..aaaaaaaapil3afuz45oxyvd3u73otqbsj4atjdorao6nvfr3yjqumnniscka",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "name": "Developers",
                        "description": "Developers",
                        "timeCreated": "2019-02-28T17:13:29.054Z",
                        "freeformTags": {},
                        "definedTags": {},
                        "lifecycleState": "ACTIVE"
                    },
                    {
                        "statements": [
                            "allow service PSM to manage all-resources in compartment managedcompartmentforpaas",
                            "allow service OracleEnterpriseManager to manage all-resources in compartment managedcompartmentforpaas",
                            "allow service PSM to manage users in tenancy where target.user.name = /__PSM*/",
                            "allow any-user to manage all-resources in compartment managedcompartmentforpaas where request.user.name = /__PSM*/",
                            "allow any-user to manage all-resources in compartment managedcompartmentforpaas where request.instance.compartment.id = 'ocid1.compartment.oc1..aaaaaaaagnxnisjq7mjmr4okjgycvaeb72whcaasb5nu4moxhpv5dcyxi5za'",
                            "allow service PSM to inspect tenant in tenancy",
                            "allow service PSM to inspect compartments in tenancy"
                        ],
                        "id": "ocid1.policy.oc1..aaaaaaaapuzolyfb2phf2rz7sjqz7odxmzkcwhgrhso3iqfvadvz35i2nceq",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "name": "PSM-root-policy",
                        "description": "PSM managed compartment root policy",
                        "timeCreated": "2019-01-31T01:12:07.959Z",
                        "freeformTags": {},
                        "definedTags": {},
                        "lifecycleState": "ACTIVE"
                    },
                    {
                        "statements": [
                            "ALLOW GROUP SecurityAudit to READ all-resources in tenancy",
                            "Allow group SecurityAudit to manage all-resources in tenancy"
                        ],
                        "id": "ocid1.policy.oc1..aaaaaaaaehgtcoif72p4yqqtnyvxdqyiuofvkuhw7denvrmfeotb4cnkkkzq",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "name": "SecurityAudit",
                        "description": "Audit Security and Configuration",
                        "timeCreated": "2019-03-07T23:48:23.892Z",
                        "freeformTags": {},
                        "definedTags": {},
                        "lifecycleState": "ACTIVE"
                    },
                    {
                        "statements": [
                            "ALLOW GROUP Administrators to manage all-resources IN TENANCY"
                        ],
                        "id": "ocid1.policy.oc1..aaaaaaaar6vu7w6u53qidx556ezcwpzzmxbfrmwudf3crgbd5rhakrimk4na",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "name": "Tenant Admin Policy",
                        "description": "Tenant Admin Policy",
                        "timeCreated": "2019-01-31T01:04:21.142Z",
                        "freeformTags": {},
                        "definedTags": {},
                        "lifecycleState": "ACTIVE"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if a policy has block storage deletion protection enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('All policies have block volume delete protection enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "statements": [
                            "Allow group Developers to manage volumes in tenancy where request.permission!='VOLUME_DELETE'",
                        ],
                        "id": "ocid1.policy.oc1..aaaaaaaapil3afuz45oxyvd3u73otqbsj4atjdorao6nvfr3yjqumnniscka",
                        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaao43aqdrzuacodg7ffqv2zeauftjyjkwhnbrugt44ympzeiblxx7q",
                        "name": "Developers",
                        "description": "Developers",
                        "timeCreated": "2019-02-28T17:13:29.054Z",
                        "freeformTags": {},
                        "definedTags": {},
                        "lifecycleState": "ACTIVE"
                    },
                ]
            );

            plugin.run(cache, {}, callback);
        });
    });
});